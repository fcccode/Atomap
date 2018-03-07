# Atomap
Single-header manual mapping injection library written in C++ for Windows operating systems. There's no license, feel free to use this in any of your personal/commercial projects.

# Usage
```c++

void Inject()
{
    Atomap::Inject("path/to/binary.dll", 1234);
    // and the second argument is the process id. that's it
}
```
