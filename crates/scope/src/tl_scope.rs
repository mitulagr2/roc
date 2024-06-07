/// Scope for top-level bindings (both lowercase and uppercase) and module imports.
/// (For scope *within* a given top-level declaration, see the decl_scope module.)
///
/// The only rule for top-level bindings is that they must have unique names;
/// they may not shadow each other.
use crate::{
    ids::{LowercaseId, ModuleId, UppercaseId},
    problem::Problem,
};
use bumpalo::{collections::vec::Vec, Bump};
use core::fmt::Debug;

/// TODO replace this with the real Vec2 that stores 1 length as u32 etc. (We can even do u16 len.)
type Vec2<'a, A, B> = Vec<'a, (A, B)>;
/// TODO replace this with the real Vec3 that stores 1 length as u32 etc. (We can even do u16 len.)
type Vec3<'a, A, B, C> = Vec<'a, (A, B, C)>;

#[derive(
    Debug,
    Clone, // TODO would like to get rid of Clone; only needed by the can::Scope that wraps this
)]
pub struct TopLevelScope<'a, LcStrId, UcStrId, ModuleStrId, Region> {
    /// Each LowercaseId is an index into this.
    lc_bindings: Vec3<'a, ModuleId, LcStrId, Region>,

    /// Each UppercaseId is an index into this.
    uc_bindings: Vec3<'a, ModuleId, UcStrId, Region>,

    /// Each ModuleId is an index into this.
    imports: Vec2<'a, ModuleStrId, Region>,
}

impl<
        'a,
        LcStrId: Copy + PartialEq + Debug,
        UcStrId: Copy + PartialEq + Debug,
        ModuleStrId: Copy + PartialEq + Debug,
        Region: Copy + Debug,
    > TopLevelScope<'a, LcStrId, UcStrId, ModuleStrId, Region>
{
    pub fn new(arena: &'a Bump, home_module_name: ModuleStrId, home_module_region: Region) -> Self {
        let by_lc_id = Vec::with_capacity_in(8, arena);
        let by_uc_id = Vec::with_capacity_in(8, arena);
        let mut by_module_id = Vec::with_capacity_in(8, arena);

        // Since ModuleId exposes ModuleId::HOME, which is hardcoded to be index 0 under the hood,
        // we have to record the home module first. Otherwise, it might not end up getting index 0!
        by_module_id.push((home_module_name, home_module_region));

        Self {
            lc_bindings: by_lc_id,
            uc_bindings: by_uc_id,
            imports: by_module_id,
        }
    }

    /// If this would shadow an existing binding that's already in scope, returns Err with
    /// the original binding's Region.
    pub fn bind_lc(
        &mut self,
        // arena: &'a Bump, // TODO uncomment this once we switch to the Vec where push takes arena
        str_id: LcStrId,
        module_id: ModuleId,
        region: Region,
    ) -> Result<LowercaseId, Region> {
        match self
            .lc_bindings
            .iter()
            .find(|(_module_id, existing_id, _region)| *existing_id == str_id)
        {
            Some((_module_id, _existing_id, existing_region)) => Err(*existing_region),
            None => {
                let lc_id = LowercaseId(self.lc_bindings.len() as u16);

                self.lc_bindings.push((module_id, str_id, region));

                Ok(lc_id)
            }
        }
    }

    /// If this would shadow an existing binding that's already in scope, returns Err with
    /// the original binding's Region.
    pub fn bind_uc(
        &mut self,
        // arena: &'a Bump, // TODO uncomment this once we switch to the Vec where push takes arena
        str_id: UcStrId,
        module_id: ModuleId,
        region: Region,
    ) -> Result<UppercaseId, Region> {
        match self
            .uc_bindings
            .iter()
            .find(|(_module_id, existing_id, _region)| *existing_id == str_id)
        {
            Some((_module_id, _existing_id, existing_region)) => Err(*existing_region),
            None => {
                let uc_id = UppercaseId(self.uc_bindings.len() as u16);

                self.uc_bindings.push((module_id, str_id, region));

                Ok(uc_id)
            }
        }
    }

    /// NOTE: When handling a module importing using `as`, always pass the `as`, not the
    /// original module name. The thing after `as` is what will be added to scope; scope
    /// does not care about (or want to know about) the original!
    ///
    /// If this would shadow an existing import that's already in scope, returns Err with
    /// the original import's Region.
    pub fn import_module(
        &mut self,
        // arena: &'a Bump, // TODO uncomment this once we switch to the Vec where push takes arena
        str_id: ModuleStrId,
        region: Region,
    ) -> Result<ModuleId, Region> {
        match self
            .imports
            .iter()
            .find(|(existing_id, _region)| *existing_id == str_id)
        {
            Some((_existing_id, existing_region)) => Err(*existing_region),
            None => {
                let module_id = ModuleId(self.imports.len() as u16);

                self.imports.push((str_id, region));

                Ok(module_id)
            }
        }
    }

    /// This is pub(crate) instead of pub because lookups must exist within decls,
    /// so only decl_scope should ever need to call this.
    pub(crate) fn lookup_lc(
        &self,
        module_id: ModuleId,
        str_id: LcStrId,
    ) -> Option<(LowercaseId, Region)> {
        self.lc_bindings.iter().enumerate().find_map(
            |(index, (haystack_module_id, haystack_str_id, region))| {
                if *haystack_str_id == str_id && *haystack_module_id == module_id {
                    Some((LowercaseId(index as u16), *region))
                } else {
                    None
                }
            },
        )
    }

    /// This is pub(crate) instead of pub because lookups must exist within decls,
    /// so only decl_scope should ever need to call this.
    pub(crate) fn lookup_uc(
        &self,
        module_id: ModuleId,
        str_id: UcStrId,
    ) -> Option<(UppercaseId, Region)> {
        self.uc_bindings.iter().enumerate().find_map(
            |(index, (haystack_module_id, haystack_str_id, region))| {
                if *haystack_str_id == str_id && *haystack_module_id == module_id {
                    Some((UppercaseId(index as u16), *region))
                } else {
                    None
                }
            },
        )
    }

    /// This is pub(crate) instead of pub because lookups must exist within decls,
    /// so only decl_scope should ever need to call this.
    pub(crate) fn lookup_module(&self, str_id: ModuleStrId) -> Option<(ModuleId, Region)> {
        self.imports
            .iter()
            .enumerate()
            .find_map(|(index, (haystack_str_id, region))| {
                if *haystack_str_id == str_id {
                    Some((ModuleId(index as u16), *region))
                } else {
                    None
                }
            })
    }

    pub fn region_from_lc_id(&self, lc_id: LowercaseId) -> Option<Region> {
        self.lc_bindings
            .get(lc_id.to_index())
            .map(|(_module_id, _str_id, region)| *region)
    }

    pub fn str_id_from_lc_id(&self, lc_id: LowercaseId) -> Option<LcStrId> {
        self.lc_bindings
            .get(lc_id.to_index())
            .map(|(_module_id, str_id, _region)| *str_id)
    }

    pub fn module_id_from_lc_id(&self, lc_id: LowercaseId) -> Option<ModuleId> {
        self.lc_bindings
            .get(lc_id.to_index())
            .map(|(module_id, _str_id, _region)| *module_id)
    }

    pub fn region_from_uc_id(&self, uc_id: UppercaseId) -> Option<Region> {
        self.uc_bindings
            .get(uc_id.to_index())
            .map(|(_module_id, _str_id, region)| *region)
    }

    pub fn str_id_from_uc_id(&self, uc_id: UppercaseId) -> Option<UcStrId> {
        self.uc_bindings
            .get(uc_id.to_index())
            .map(|(_module_id, str_id, _region)| *str_id)
    }

    pub fn module_id_from_uc_id(&self, uc_id: UppercaseId) -> Option<ModuleId> {
        self.uc_bindings
            .get(uc_id.to_index())
            .map(|(module_id, _str_id, _region)| *module_id)
    }

    pub fn region_from_module_id(&self, module_id: ModuleId) -> Option<Region> {
        self.imports
            .get(module_id.to_index())
            .map(|(_str_id, region)| *region)
    }

    pub fn str_id_from_module_id(&self, module_id: ModuleId) -> Option<ModuleStrId> {
        self.imports
            .get(module_id.to_index())
            .map(|(str_id, _region)| *str_id)
    }

    /// Make sure we didn't overflow anything - e.g. that we didn't hand
    /// out more LowercaseIds than we support (which would have caused
    /// errors due to u16 casting resulting in incorrect numbers).
    ///
    /// It's essentially inconceivable that this would come up in practice,
    /// but if it does (or if someone is fuzzing the compiler), we should
    /// still handle it with a graceful error!
    pub fn validate(
        &self,
        arena: &'a Bump,
    ) -> Vec<'a, Problem<LcStrId, UcStrId, ModuleStrId, Region>> {
        let mut problems = Vec::new_in(arena);

        if self.lc_bindings.len() >= u16::MAX as usize {
            problems.push(Problem::TooManyBindings);
        }

        // Note: module imports and uppercase bindings each go on their own lines,
        // syntactically, so they actually cannot overflow. Only lowercase bindings
        // can possibly overflow, which could theoretically happen due to top-level destructuring.
        problems
    }

    pub(crate) fn num_lc_bindings(&self) -> usize {
        self.lc_bindings.len()
    }

    pub(crate) fn num_uc_bindings(&self) -> usize {
        self.uc_bindings.len()
    }

    pub(crate) fn num_imports(&self) -> usize {
        self.imports.len()
    }
}

// #[cfg(test)]
// mod scope_tests {
//     use super::{Scope, Vec2};

//     type IdentId = usize;
//     type Region = usize;
//     type TestScope = Scope<IdentId, Region>;

//     fn new_scope(
//         lowercase: &[IdentId],
//         uppercase: &[IdentId],
//     ) -> (TestScope, Vec2<IdentId, Region>) {
//         Scope::new(
//             lowercase
//                 .iter()
//                 .enumerate()
//                 .map(|(region, ident_id)| (*ident_id, region)),
//             uppercase
//                 .iter()
//                 .enumerate()
//                 .map(|(region, ident_id)| (*ident_id, region)),
//         )
//     }

//     fn push_bindings(scope: &mut TestScope, ident_ids: &[IdentId]) {
//         scope.push();

//         for &ident_id in ident_ids {
//             scope.add_lc_binding(ident_id, scope.by_lc_id.len());
//         }
//     }

//     #[test]
//     fn empty_top_level() {
//         let (scope, shadowed) = new_scope(&[], &[]);

//         assert_eq!(shadowed, Vec::new());
//         assert_eq!(scope.lookup_lc_in_nested(0), None);
//         assert_eq!(scope.lookup_lc_in_top_level(0), None);
//     }

//     #[test]
//     fn top_level_lookup() {
//         let top_level = &[1, 2, 3];
//         let (scope, shadowed) = new_scope(top_level, &[]);

//         assert_eq!(shadowed, Vec::new());

//         for &ident_id in top_level {
//             assert!(
//                 scope.lookup_lc_in_top_level(ident_id).is_some(),
//                 "Expected {ident_id} to be in top-level, but it wasn't."
//             );
//             assert!(
//                 scope.lookup_lc_in_nested(ident_id).is_none(),
//                 "Expected {ident_id} to NOT be in nested defs, but it was."
//             );
//         }

//         assert_eq!(scope.lookup_lc_in_top_level(0), None);
//         assert_eq!(scope.lookup_lc_in_top_level(top_level.len() + 1), None);

//         assert_eq!(scope.lookup_lc_in_nested(0), None);
//         assert_eq!(scope.lookup_lc_in_nested(top_level.len() + 1), None);
//     }

//     #[test]
//     fn nested_lookup_not_shadowing() {
//         let top_level = &[1, 2, 3];
//         let (mut scope, shadowed) = new_scope(top_level, &[]);
//         assert_eq!(shadowed, Vec::new());
//         let nested_scope = &[4, 5, 6];

//         push_bindings(&mut scope, nested_scope);

//         for &ident_id in nested_scope {
//             assert!(
//                 scope.lookup_lc_unqualified(ident_id).is_some(),
//                 "Expected {ident_id} to be in nested scope, but an unqualified lookup failed."
//             );
//         }
//     }

//     #[test]
//     fn nested_lookup_shadowing_top_level() {
//         let top_level = &[1, 2, 3];
//         let (mut scope, shadowed) = new_scope(top_level, &[]);
//         assert_eq!(shadowed, Vec::new());
//         let nested_scope = &[2, 3, 4];

//         push_bindings(&mut scope, nested_scope);

//         for (index, ident_id) in nested_scope.iter().copied().enumerate() {
//             let opt_lc_id = scope.lookup_lc_unqualified(ident_id);

//             assert!(
//                 opt_lc_id.is_some(),
//                 "Expected {ident_id} to be in nested scope, but an unqualified lookup failed."
//             );

//             let lc_id = opt_lc_id.unwrap();

//             assert!(
//                 lc_id.0 as usize >= top_level.len(),
//                 "Lookup for {ident_id} had a ScopeId of {}, which was not greater than or equal to number of top-level defs ({}), which was expecte because it shadowed a top-level binding.",
//                 lc_id.0,
//                 top_level.len()
//             );

//             assert_eq!(ident_id, scope.ident_id_from_lc_id(lc_id));
//             assert_eq!(index + top_level.len(), scope.region_from_lc_id(lc_id));
//         }
//     }

//     #[test]
//     fn nested_lookup_in_out_shadowing() {
//         let top_level = &[1, 2, 3];
//         let (mut scope, shadowed) = new_scope(top_level, &[]);
//         assert_eq!(shadowed, Vec::new());
//         push_bindings(&mut scope, &[2, 3, 4, 5]);
//         push_bindings(&mut scope, &[3, 4, 5, 6, 42]);

//         let total_bindings_before_pop = scope.by_lc_id.len();

//         {
//             assert!(
//                 scope.lookup_lc_unqualified(42).is_some(),
//                 "Expected lookup for 42 to be in scope before the pop(), but it was not in scope."
//             );

//             scope.pop();

//             assert!(
//                 scope.lookup_lc_unqualified(42).is_none(),
//                 "Expected lookup for 42 to be out of scope after the pop(), but it was in scope."
//             );
//         }

//         push_bindings(&mut scope, &[1, 3, 4, 5, 7]);

//         assert!(
//             scope.lookup_lc_unqualified(42).is_none(),
//             "Expected lookup for 42 to be out of scope after the pop() and the new bindings, but it was in scope."
//         );

//         assert!(
//             scope.lookup_lc_unqualified(7).is_some(),
//             "Expected lookup for 7 to be in scope after the new bindings, but it was not in scope."
//         );

//         for ident_id in [3, 4, 5] {
//             let opt_lc_id = scope.lookup_lc_unqualified(ident_id);

//             assert!(
//                 opt_lc_id.is_some(),
//                 "Expected {ident_id} to be in nested scope, but an unqualified lookup failed."
//             );

//             let lc_id = opt_lc_id.unwrap();

//             assert!(
//                 lc_id.0 as usize >= total_bindings_before_pop,
//                 "Lookup for {ident_id} had a ScopeId of {}, which was not greater than or equal to number of expected bindings at this point ({total_bindings_before_pop})",
//                 lc_id.0,
//             );
//         }
//     }
// }