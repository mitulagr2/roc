use crate::annotation::{Formattable, Newlines, Parens};
use crate::def::fmt_def;
use crate::pattern::fmt_pattern;
use crate::spaces::{
    add_spaces, fmt_comments_only, fmt_condition_spaces, fmt_spaces, is_comment, newline, INDENT,
};
use bumpalo::collections::{String, Vec};
use roc_module::operator::{self, BinOp};
use roc_parse::ast::{AssignedField, Base, CommentOrNewline, Expr, Pattern, WhenBranch};
use roc_region::all::Located;

impl<'a> Formattable<'a> for Expr<'a> {
    fn is_multiline(&self) -> bool {
        use roc_parse::ast::Expr::*;
        // TODO cache these answers using a Map<Pointer, bool>, so
        // we don't have to traverse subexpressions repeatedly

        match self {
            // Return whether these spaces contain any Newlines
            SpaceBefore(_sub_expr, spaces) | SpaceAfter(_sub_expr, spaces) => {
                debug_assert!(!spaces.is_empty());

                // "spaces" always contain either a newline or comment, and comments have newlines
                true
            }

            // These expressions never have newlines
            Float(_)
            | Num(_)
            | NonBase10Int { .. }
            | Str(_)
            | Access(_, _)
            | AccessorFunction(_)
            | Var { .. }
            | MalformedIdent(_)
            | MalformedClosure
            | GlobalTag(_)
            | PrivateTag(_) => false,

            // These expressions always have newlines
            Defs(_, _) | When(_, _) => true,

            List(elems) => elems.iter().any(|loc_expr| loc_expr.is_multiline()),

            BlockStr(lines) => lines.len() > 1,
            Apply(loc_expr, args, _) => {
                loc_expr.is_multiline() || args.iter().any(|loc_arg| loc_arg.is_multiline())
            }

            If(loc_cond, loc_if_true, loc_if_false) => {
                loc_cond.is_multiline() || loc_if_true.is_multiline() || loc_if_false.is_multiline()
            }

            BinOp((loc_left, _, loc_right)) => {
                let next_is_multiline_bin_op: bool = match &loc_right.value {
                    Expr::BinOp((_, _, nested_loc_right)) => nested_loc_right.is_multiline(),
                    _ => false,
                };

                next_is_multiline_bin_op || loc_left.is_multiline() || loc_right.is_multiline()
            }

            UnaryOp(loc_subexpr, _) | PrecedenceConflict(_, _, _, loc_subexpr) => {
                loc_subexpr.is_multiline()
            }

            ParensAround(subexpr) | Nested(subexpr) => subexpr.is_multiline(),

            Closure(loc_patterns, loc_body) => {
                // check the body first because it's more likely to be multiline
                loc_body.is_multiline()
                    || loc_patterns
                        .iter()
                        .any(|loc_pattern| loc_pattern.is_multiline())
            }

            Record { fields, .. } => fields
                .iter()
                .any(|loc_field| is_multiline_field(&loc_field.value)),
        }
    }

    fn format_with_options(
        &self,
        buf: &mut String<'a>,
        parens: Parens,
        newlines: Newlines,
        indent: u16,
    ) {
        use self::Expr::*;

        let format_newlines = newlines == Newlines::Yes;
        let apply_needs_parens = parens == Parens::InApply;

        match self {
            SpaceBefore(sub_expr, spaces) => {
                if format_newlines {
                    fmt_spaces(buf, spaces.iter(), indent);
                } else {
                    fmt_comments_only(buf, spaces.iter(), indent);
                }
                fmt_expr(buf, sub_expr, indent, apply_needs_parens, format_newlines);
            }
            SpaceAfter(sub_expr, spaces) => {
                fmt_expr(buf, sub_expr, indent, apply_needs_parens, format_newlines);
                if format_newlines {
                    fmt_spaces(buf, spaces.iter(), indent);
                } else {
                    fmt_comments_only(buf, spaces.iter(), indent);
                }
            }
            ParensAround(sub_expr) => {
                buf.push('(');
                fmt_expr(buf, sub_expr, indent, false, true);
                buf.push(')');
            }
            Str(string) => {
                buf.push('"');
                buf.push_str(string);
                buf.push('"');
            }
            Var { module_name, ident } => {
                if !module_name.is_empty() {
                    buf.push_str(module_name);
                    buf.push('.');
                }

                buf.push_str(ident);
            }
            Apply(loc_expr, loc_args, _) => {
                if apply_needs_parens {
                    buf.push('(');
                }

                fmt_expr(buf, &loc_expr.value, indent, true, true);

                let multiline_args = loc_args
                    .iter()
                    .any(|loc_arg| is_multiline_expr(&loc_arg.value));

                if multiline_args {
                    let arg_indent = indent + INDENT;

                    for loc_arg in loc_args {
                        newline(buf, arg_indent);
                        fmt_expr(buf, &loc_arg.value, arg_indent, true, false);
                    }
                } else {
                    for loc_arg in loc_args {
                        buf.push(' ');
                        fmt_expr(buf, &loc_arg.value, indent, true, true);
                    }
                }

                if apply_needs_parens {
                    buf.push(')');
                }
            }
            BlockStr(lines) => {
                buf.push_str("\"\"\"");
                for line in lines.iter() {
                    buf.push_str(line);
                }
                buf.push_str("\"\"\"");
            }
            Num(string) | Float(string) | GlobalTag(string) | PrivateTag(string) => {
                buf.push_str(string)
            }
            NonBase10Int {
                base,
                string,
                is_negative,
            } => {
                if *is_negative {
                    buf.push('-');
                }

                match base {
                    Base::Hex => buf.push_str("0x"),
                    Base::Octal => buf.push_str("0o"),
                    Base::Binary => buf.push_str("0b"),
                    Base::Decimal => { /* nothing */ }
                }

                buf.push_str(string);
            }
            Record { fields, update } => {
                fmt_record(buf, *update, fields, indent, parens);
            }
            Closure(loc_patterns, loc_ret) => {
                fmt_closure(buf, loc_patterns, loc_ret, indent);
            }
            Defs(defs, ret) => {
                // It should theoretically be impossible to *parse* an empty defs list.
                // (Canonicalization can remove defs later, but that hasn't happened yet!)
                debug_assert!(!defs.is_empty());

                // The first def is located last in the list, because it gets added there
                // with .push() for efficiency. (The order of parsed defs doesn't
                // matter because canonicalization sorts them anyway.)
                // The other defs in the list are in their usual order.
                //
                // But, the first element of `defs` could be the annotation belonging to the final
                // element, so format the annotation first.
                let it = defs.iter().peekable();

                /*
                // so if it exists, format the annotation
                if let Some(Located {
                    value: Def::Annotation(_, _),
                    ..
                }) = it.peek()
                {
                    let def = it.next().unwrap();
                    fmt_def(buf, &def.value, indent);
                }

                // then (using iter_back to get the last value of the `defs` vec) format the first body
                if let Some(loc_first_def) = it.next_back() {
                    fmt_def(buf, &loc_first_def.value, indent);
                }
                */

                // then format the other defs in order
                for loc_def in it {
                    fmt_def(buf, &loc_def.value, indent);
                }

                let empty_line_before_return = empty_line_before_expr(&ret.value);

                if !empty_line_before_return {
                    buf.push('\n');
                }

                // Even if there were no defs, which theoretically should never happen,
                // still print the return value.
                fmt_expr(buf, &ret.value, indent, false, true);
            }
            If(loc_condition, loc_then, loc_else) => {
                fmt_if(buf, loc_condition, loc_then, loc_else, indent);
            }
            When(loc_condition, branches) => fmt_when(buf, loc_condition, branches, indent),
            List(loc_items) => {
                fmt_list(buf, &loc_items, indent);
            }
            BinOp((loc_left_side, bin_op, loc_right_side)) => fmt_bin_op(
                buf,
                loc_left_side,
                bin_op,
                loc_right_side,
                false,
                apply_needs_parens,
                indent,
            ),
            UnaryOp(sub_expr, unary_op) => {
                match &unary_op.value {
                    operator::UnaryOp::Negate => {
                        buf.push('-');
                    }
                    operator::UnaryOp::Not => {
                        buf.push('!');
                    }
                }

                fmt_expr(
                    buf,
                    &sub_expr.value,
                    indent,
                    apply_needs_parens,
                    format_newlines,
                );
            }
            Nested(nested_expr) => {
                fmt_expr(
                    buf,
                    nested_expr,
                    indent,
                    apply_needs_parens,
                    format_newlines,
                );
            }
            AccessorFunction(key) => {
                buf.push('.');
                buf.push_str(key);
            }
            Access(expr, key) => {
                fmt_expr(buf, expr, indent, apply_needs_parens, true);
                buf.push('.');
                buf.push_str(key);
            }
            MalformedIdent(_) => {}
            MalformedClosure => {}
            PrecedenceConflict(_, _, _, _) => {}
        }
    }
}

pub fn fmt_expr<'a>(
    buf: &mut String<'a>,
    expr: &'a Expr<'a>,
    indent: u16,
    apply_needs_parens: bool,
    format_newlines: bool,
) {
    let parens = if apply_needs_parens {
        Parens::InApply
    } else {
        Parens::NotNeeded
    };

    let newlines = if format_newlines {
        Newlines::Yes
    } else {
        Newlines::No
    };

    expr.format_with_options(buf, parens, newlines, indent)
}

fn fmt_bin_op<'a>(
    buf: &mut String<'a>,
    loc_left_side: &'a Located<Expr<'a>>,
    loc_bin_op: &'a Located<BinOp>,
    loc_right_side: &'a Located<Expr<'a>>,
    part_of_multi_line_bin_ops: bool,
    apply_needs_parens: bool,
    indent: u16,
) {
    fmt_expr(buf, &loc_left_side.value, indent, apply_needs_parens, false);

    let is_multiline = is_multiline_expr(&loc_right_side.value)
        || is_multiline_expr(&loc_left_side.value)
        || part_of_multi_line_bin_ops;

    if is_multiline {
        newline(buf, indent + INDENT)
    } else {
        buf.push(' ');
    }

    match &loc_bin_op.value {
        operator::BinOp::Caret => buf.push('^'),
        operator::BinOp::Star => buf.push('*'),
        operator::BinOp::Slash => buf.push('/'),
        operator::BinOp::DoubleSlash => buf.push_str("//"),
        operator::BinOp::Percent => buf.push('%'),
        operator::BinOp::DoublePercent => buf.push_str("%%"),
        operator::BinOp::Plus => buf.push('+'),
        operator::BinOp::Minus => buf.push('-'),
        operator::BinOp::Equals => buf.push_str("=="),
        operator::BinOp::NotEquals => buf.push_str("!="),
        operator::BinOp::LessThan => buf.push('<'),
        operator::BinOp::GreaterThan => buf.push('>'),
        operator::BinOp::LessThanOrEq => buf.push_str("<="),
        operator::BinOp::GreaterThanOrEq => buf.push_str(">="),
        operator::BinOp::And => buf.push_str("&&"),
        operator::BinOp::Or => buf.push_str("||"),
        operator::BinOp::Pizza => buf.push_str("|>"),
    }

    buf.push(' ');

    match &loc_right_side.value {
        Expr::BinOp((nested_left_side, nested_bin_op, nested_right_side)) => {
            fmt_bin_op(
                buf,
                nested_left_side,
                nested_bin_op,
                nested_right_side,
                is_multiline,
                apply_needs_parens,
                indent,
            );
        }

        _ => {
            fmt_expr(buf, &loc_right_side.value, indent, apply_needs_parens, true);
        }
    }
}

pub fn fmt_list<'a>(buf: &mut String<'a>, loc_items: &[&Located<Expr<'a>>], indent: u16) {
    buf.push('[');

    let mut iter = loc_items.iter().peekable();

    let is_multiline = loc_items.iter().any(|item| is_multiline_expr(&item.value));

    let item_indent = if is_multiline {
        indent + INDENT
    } else {
        indent
    };

    while let Some(item) = iter.next() {
        if is_multiline {
            match &item.value {
                Expr::SpaceBefore(expr_below, spaces_above_expr) => {
                    newline(buf, item_indent);
                    fmt_comments_only(buf, spaces_above_expr.iter(), item_indent);

                    match &expr_below {
                        Expr::SpaceAfter(expr_above, spaces_below_expr) => {
                            fmt_expr(buf, expr_above, item_indent, false, false);

                            if iter.peek().is_some() {
                                buf.push(',');
                            }

                            fmt_condition_spaces(buf, spaces_below_expr.iter(), item_indent);
                        }
                        _ => {
                            fmt_expr(buf, expr_below, item_indent, false, false);
                            if iter.peek().is_some() {
                                buf.push(',');
                            }
                        }
                    }
                }

                Expr::SpaceAfter(sub_expr, spaces) => {
                    newline(buf, item_indent);

                    fmt_expr(buf, sub_expr, item_indent, false, false);

                    if iter.peek().is_some() {
                        buf.push(',');
                    }

                    fmt_condition_spaces(buf, spaces.iter(), item_indent);
                }

                _ => {
                    newline(buf, item_indent);
                    item.format_with_options(buf, Parens::NotNeeded, Newlines::Yes, item_indent);
                    if iter.peek().is_some() {
                        buf.push(',');
                    }
                }
            }
        } else {
            buf.push(' ');
            item.format_with_options(buf, Parens::NotNeeded, Newlines::Yes, item_indent);
            if iter.peek().is_some() {
                buf.push(',');
            }
        }
    }

    if is_multiline {
        newline(buf, indent);
    }

    if !loc_items.is_empty() && !is_multiline {
        buf.push(' ');
    }
    buf.push(']');
}

pub fn fmt_field<'a>(
    buf: &mut String<'a>,
    assigned_field: &'a AssignedField<'a, Expr<'a>>,
    is_multiline: bool,
    indent: u16,
    apply_needs_parens: bool,
) {
    use self::AssignedField::*;

    match assigned_field {
        LabeledValue(name, spaces, value) => {
            if is_multiline {
                newline(buf, indent);
            }

            buf.push_str(name.value);

            if !spaces.is_empty() {
                fmt_spaces(buf, spaces.iter(), indent);
            }

            buf.push(':');
            buf.push(' ');
            fmt_expr(buf, &value.value, indent, apply_needs_parens, true);
        }
        LabelOnly(name) => {
            if is_multiline {
                newline(buf, indent);
            }

            buf.push_str(name.value);
        }
        AssignedField::SpaceBefore(sub_expr, spaces) => {
            fmt_comments_only(buf, spaces.iter(), indent);
            fmt_field(buf, sub_expr, is_multiline, indent, apply_needs_parens);
        }
        AssignedField::SpaceAfter(sub_expr, spaces) => {
            fmt_field(buf, sub_expr, is_multiline, indent, apply_needs_parens);
            fmt_comments_only(buf, spaces.iter(), indent);
        }
        Malformed(string) => buf.push_str(string),
    }
}

pub fn empty_line_before_expr<'a>(expr: &'a Expr<'a>) -> bool {
    use roc_parse::ast::Expr::*;

    match expr {
        SpaceBefore(_, spaces) => {
            let mut has_at_least_one_newline = false;

            for comment_or_newline in spaces.iter() {
                match comment_or_newline {
                    CommentOrNewline::Newline => {
                        if has_at_least_one_newline {
                            return true;
                        } else {
                            has_at_least_one_newline = true;
                        }
                    }
                    CommentOrNewline::LineComment(_) | CommentOrNewline::DocComment(_) => {}
                }
            }

            false
        }

        Nested(nested_expr) => empty_line_before_expr(nested_expr),

        _ => false,
    }
}

pub fn is_multiline_pattern<'a>(pattern: &'a Pattern<'a>) -> bool {
    pattern.is_multiline()
}

pub fn is_multiline_expr<'a>(expr: &'a Expr<'a>) -> bool {
    use roc_parse::ast::Expr::*;
    // TODO cache these answers using a Map<Pointer, bool>, so
    // we don't have to traverse subexpressions repeatedly

    match expr {
        // Return whether these spaces contain any Newlines
        SpaceBefore(_, spaces) | SpaceAfter(_, spaces) => {
            debug_assert!(!spaces.is_empty());

            // "spaces" always contain either a newline or comment, and comments have newlines
            true
        }

        // These expressions never have newlines
        Float(_)
        | Num(_)
        | NonBase10Int { .. }
        | Str(_)
        | Access(_, _)
        | AccessorFunction(_)
        | Var { .. }
        | MalformedIdent(_)
        | MalformedClosure
        | GlobalTag(_)
        | PrivateTag(_) => false,

        // These expressions always have newlines
        Defs(_, _) | When(_, _) => true,

        List(elems) => elems
            .iter()
            .any(|loc_expr| is_multiline_expr(&loc_expr.value)),

        BlockStr(lines) => lines.len() > 1,
        Apply(loc_expr, args, _) => {
            is_multiline_expr(&loc_expr.value)
                || args.iter().any(|loc_arg| is_multiline_expr(&loc_arg.value))
        }

        If(loc_cond, loc_if_true, loc_if_false) => {
            is_multiline_expr(&loc_cond.value)
                || is_multiline_expr(&loc_if_true.value)
                || is_multiline_expr(&loc_if_false.value)
        }

        BinOp((loc_left, _, loc_right)) => {
            let next_is_multiline_bin_op: bool = match &loc_right.value {
                Expr::BinOp((_, _, nested_loc_right)) => is_multiline_expr(&nested_loc_right.value),
                _ => false,
            };

            is_multiline_expr(&loc_left.value)
                || is_multiline_expr(&loc_right.value)
                || next_is_multiline_bin_op
        }

        UnaryOp(loc_subexpr, _) | PrecedenceConflict(_, _, _, loc_subexpr) => {
            is_multiline_expr(&loc_subexpr.value)
        }

        ParensAround(subexpr) | Nested(subexpr) => is_multiline_expr(&subexpr),

        Closure(loc_patterns, loc_body) => {
            // check the body first because it's more likely to be multiline
            is_multiline_expr(&loc_body.value)
                || loc_patterns
                    .iter()
                    .any(|loc_pattern| is_multiline_pattern(&loc_pattern.value))
        }

        Record { fields, .. } => fields
            .iter()
            .any(|loc_field| is_multiline_field(&loc_field.value)),
    }
}

pub fn is_multiline_field<'a, Val>(field: &'a AssignedField<'a, Val>) -> bool {
    use self::AssignedField::*;

    match field {
        LabeledValue(_, spaces, _) => !spaces.is_empty(),
        LabelOnly(_) => false,
        AssignedField::SpaceBefore(_, _) | AssignedField::SpaceAfter(_, _) => true,
        Malformed(text) => text.chars().any(|c| c == '\n'),
    }
}

fn fmt_when<'a>(
    buf: &mut String<'a>,
    loc_condition: &'a Located<Expr<'a>>,
    branches: &[&'a WhenBranch<'a>],
    indent: u16,
) {
    let is_multiline_condition = is_multiline_expr(&loc_condition.value);
    buf.push_str(
        "\
         when",
    );
    if is_multiline_condition {
        let condition_indent = indent + INDENT;

        match &loc_condition.value {
            Expr::SpaceBefore(expr_below, spaces_above_expr) => {
                fmt_condition_spaces(buf, spaces_above_expr.iter(), condition_indent);
                newline(buf, condition_indent);
                match &expr_below {
                    Expr::SpaceAfter(expr_above, spaces_below_expr) => {
                        fmt_expr(buf, &expr_above, condition_indent, false, false);
                        fmt_condition_spaces(buf, spaces_below_expr.iter(), condition_indent);
                        newline(buf, indent);
                    }
                    _ => {
                        fmt_expr(buf, &expr_below, condition_indent, false, false);
                    }
                }
            }
            _ => {
                newline(buf, condition_indent);
                fmt_expr(buf, &loc_condition.value, condition_indent, false, false);
                newline(buf, indent);
            }
        }
    } else {
        buf.push(' ');
        fmt_expr(buf, &loc_condition.value, indent, false, true);
        buf.push(' ');
    }
    buf.push_str("is\n");

    let mut it = branches.iter().peekable();
    while let Some(branch) = it.next() {
        let patterns = &branch.patterns;
        let expr = &branch.value;
        add_spaces(buf, indent + INDENT);
        let (first_pattern, rest) = patterns.split_first().unwrap();
        let is_multiline = match rest.last() {
            None => false,
            Some(last_pattern) => first_pattern.region.start_line != last_pattern.region.end_line,
        };

        fmt_pattern(
            buf,
            &first_pattern.value,
            indent + INDENT,
            Parens::NotNeeded,
        );
        for when_pattern in rest {
            if is_multiline {
                buf.push_str("\n");
                add_spaces(buf, indent + INDENT);
                buf.push_str("| ");
            } else {
                buf.push_str(" | ");
            }
            fmt_pattern(buf, &when_pattern.value, indent + INDENT, Parens::NotNeeded);
        }

        if let Some(guard_expr) = &branch.guard {
            buf.push_str(" if ");
            fmt_expr(buf, &guard_expr.value, indent + INDENT, false, true);
        }

        buf.push_str(" ->\n");

        add_spaces(buf, indent + (INDENT * 2));
        match expr.value {
            Expr::SpaceBefore(nested, spaces) => {
                fmt_comments_only(buf, spaces.iter(), indent + (INDENT * 2));
                fmt_expr(buf, &nested, indent + (INDENT * 2), false, true);
            }
            _ => {
                fmt_expr(buf, &expr.value, indent + (INDENT * 2), false, true);
            }
        }

        if it.peek().is_some() {
            buf.push('\n');
            buf.push('\n');
        }
    }
}

fn fmt_if<'a>(
    buf: &mut String<'a>,
    loc_condition: &'a Located<Expr<'a>>,
    loc_then: &'a Located<Expr<'a>>,
    loc_else: &'a Located<Expr<'a>>,
    indent: u16,
) {
    let is_multiline_then = is_multiline_expr(&loc_then.value);
    let is_multiline_else = is_multiline_expr(&loc_else.value);
    let is_multiline_condition = is_multiline_expr(&loc_condition.value);
    let is_multiline = is_multiline_then || is_multiline_else || is_multiline_condition;

    let return_indent = if is_multiline {
        indent + INDENT
    } else {
        indent
    };

    buf.push_str("if");

    if is_multiline_condition {
        match &loc_condition.value {
            Expr::SpaceBefore(expr_below, spaces_above_expr) => {
                fmt_condition_spaces(buf, spaces_above_expr.iter(), return_indent);
                newline(buf, return_indent);

                match &expr_below {
                    Expr::SpaceAfter(expr_above, spaces_below_expr) => {
                        fmt_expr(buf, &expr_above, return_indent, false, false);
                        fmt_condition_spaces(buf, spaces_below_expr.iter(), return_indent);
                        newline(buf, indent);
                    }

                    _ => {
                        fmt_expr(buf, &expr_below, return_indent, false, false);
                    }
                }
            }

            Expr::SpaceAfter(expr_above, spaces_below_expr) => {
                newline(buf, return_indent);
                fmt_expr(buf, &expr_above, return_indent, false, false);
                fmt_condition_spaces(buf, spaces_below_expr.iter(), return_indent);
                newline(buf, indent);
            }

            _ => {
                newline(buf, return_indent);
                fmt_expr(buf, &loc_condition.value, return_indent, false, false);
                newline(buf, indent);
            }
        }
    } else {
        buf.push(' ');
        fmt_expr(buf, &loc_condition.value, indent, false, true);
        buf.push(' ');
    }

    buf.push_str("then");

    if is_multiline {
        match &loc_then.value {
            Expr::SpaceBefore(expr_below, spaces_below) => {
                let any_comments_below = spaces_below.iter().any(is_comment);

                if !any_comments_below {
                    newline(buf, return_indent);
                }

                fmt_condition_spaces(buf, spaces_below.iter(), return_indent);

                if any_comments_below {
                    newline(buf, return_indent);
                }

                match &expr_below {
                    Expr::SpaceAfter(expr_above, spaces_above) => {
                        fmt_expr(buf, &expr_above, return_indent, false, false);

                        fmt_condition_spaces(buf, spaces_above.iter(), return_indent);
                        newline(buf, indent);
                    }

                    _ => {
                        fmt_expr(buf, &expr_below, return_indent, false, false);
                    }
                }
            }
            _ => {
                fmt_expr(buf, &loc_condition.value, return_indent, false, false);
            }
        }
    } else {
        buf.push_str(" ");
        fmt_expr(buf, &loc_then.value, return_indent, false, false);
    }

    if is_multiline {
        buf.push_str("else");
        newline(buf, return_indent);
    } else {
        buf.push_str(" else ");
    }

    fmt_expr(buf, &loc_else.value, return_indent, false, false);
}

pub fn fmt_closure<'a>(
    buf: &mut String<'a>,
    loc_patterns: &'a Vec<'a, Located<Pattern<'a>>>,
    loc_ret: &'a Located<Expr<'a>>,
    indent: u16,
) {
    use self::Expr::*;

    buf.push('\\');

    let arguments_are_multiline = loc_patterns
        .iter()
        .any(|loc_pattern| is_multiline_pattern(&loc_pattern.value));

    // If the arguments are multiline, go down a line and indent.
    let indent = if arguments_are_multiline {
        indent + INDENT
    } else {
        indent
    };

    let mut it = loc_patterns.iter().peekable();

    while let Some(loc_pattern) = it.next() {
        fmt_pattern(buf, &loc_pattern.value, indent, Parens::NotNeeded);

        if it.peek().is_some() {
            if arguments_are_multiline {
                buf.push(',');
                newline(buf, indent);
            } else {
                buf.push_str(", ");
            }
        }
    }

    if arguments_are_multiline {
        newline(buf, indent);
    } else {
        buf.push(' ');
    }

    buf.push_str("->");

    let is_multiline = is_multiline_expr(&loc_ret.value);

    // If the body is multiline, go down a line and indent.
    let body_indent = if is_multiline {
        indent + INDENT
    } else {
        indent
    };

    // the body of the Closure can be on the same line, or
    // on a new line. If it's on the same line, insert a space.

    match &loc_ret.value {
        SpaceBefore(_, _) => {
            // the body starts with (first comment and then) a newline
            // do nothing
        }
        _ => {
            // add a space after the `->`
            buf.push(' ');
        }
    };

    fmt_expr(buf, &loc_ret.value, body_indent, false, true);
}

pub fn fmt_record<'a>(
    buf: &mut String<'a>,
    update: Option<&'a Located<Expr<'a>>>,
    loc_fields: &[Located<AssignedField<'a, Expr<'a>>>],
    indent: u16,
    apply_needs_parens: Parens,
) {
    buf.push('{');

    match update {
        None => {}
        // We are presuming this to be a Var()
        // If it wasnt a Var() we would not have made
        // it this far. For example "{ 4 & hello = 9 }"
        // doesnt make sense.
        Some(record_var) => {
            buf.push(' ');
            record_var.format(buf, indent);
            buf.push_str(" &");
        }
    }

    let is_multiline = loc_fields
        .iter()
        .any(|loc_field| is_multiline_field(&loc_field.value));

    let mut iter = loc_fields.iter().peekable();
    let field_indent = if is_multiline {
        indent + INDENT
    } else {
        if !loc_fields.is_empty() {
            buf.push(' ');
        }

        indent
    };

    let newlines = if is_multiline {
        Newlines::Yes
    } else {
        Newlines::No
    };

    while let Some(field) = iter.next() {
        field.format_with_options(buf, Parens::NotNeeded, newlines, field_indent);

        if iter.peek().is_some() {
            buf.push(',');

            if !is_multiline {
                buf.push(' ');
            }
        }
    }

    if is_multiline {
        newline(buf, indent)
    } else if !loc_fields.is_empty() {
        buf.push(' ');
    }

    buf.push('}');
}
