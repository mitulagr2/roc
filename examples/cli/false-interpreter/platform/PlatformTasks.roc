hosted PlatformTasks
    exposes [FileHandle, openFile, closeFile, withFileOpen, getFileLine, getFileBytes, putLine, putRaw, getLine, getChar]
    imports []

FileHandle := Box {}

openFile : Str -> Task FileHandle {}

closeFile : FileHandle -> Task {} {}

withFileOpen : Str, (FileHandle -> Task ok err) -> Task {} {}

getFileLine : FileHandle -> Task Str {}

getFileBytes : FileHandle -> Task (List U8) {}

putLine : Str -> Task {} {}

putRaw : Str -> Task {} {}

getLine : Task Str {}

getChar : Task U8 {}
