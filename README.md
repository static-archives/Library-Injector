# Library-Injector
This is a manual map injector for x86_64 processes.
But instead of DLL's, this maps the archive objects of static libraries (.lib files) into a process.

# Why .lib files?
Most anti-cheats in games are unable to sanitize every memory page in existence. There's almost always going to be a place you can inject code to, that slips under the radar. However, what you can do with that knowledge all comes down to the size of these pages.
All you need is a 1kb rwx page to bypass 90% of an anti-cheat, or leverage a larger scale bypass.
That's also enough memory to set up hooks and monitor the process.

The problem with DLL's is that they're usually compiled with heavy runtimes by default, especially if you're using visual studios.
This adds 10kb to the DLL right off the bat. There's also no way to disable it.

By compiling as a library file, it outputs the absolute bare-minimum. We get only the code that we write.
This can be used for injecting ASM stubs with ease, using the vs masm assembler.

# What's good about this injector?
This archive injector gives you full control of the symbols, data and code in your binary, including where it will map your binary to and from.
You can set the boundaries -- you can set up multiple injection spots and it will scatter your code across as many RWX pages as you'd like.
You also set the boundaries of where you want it to write your data and rdata sections to, RW and R memory pages respectively.

# Limitations
Upon developing this parser for COFF headers I noticed an unfortunate limitation in lib files, but it's nothing tragic.
There is no offset anywhere to be found if you define more than one function body in the same source file, which means 
while writing this I was unable to pinpoint where the function body begins if there is another one in the same archive object...
This means you can only define one function body per source file (.c/.cpp/.asm).
But you can put all your extern function declarations in the same header file.

# Notice
I highly recommend using extern "C" for any and all function or variable definitions in headers, so that their symbols are easy to locate.




