# knuckle [![Build Status](https://travis-ci.org/erik/knuckle.svg?branch=master)](https://travis-ci.org/erik/knuckle)

**WARNING:** This library is not ready! It should be treated as insecure until proven otherwise.

Knuckle is a library designed to make common cryptography operations in Rust as easy and secure as possible. It does this by hiding all unnecessary implementation details, so rather than knowing you're using the [Salsa20 cipher](http://en.wikipedia.org/wiki/Salsa20), you just need to use a `secretbox` to perform symmetric key encryption.

Knuckle is built on top of the NaCl library, which has the same goal of being a sort of cryptographic black box. Knuckle provides direct access to the NaCl API, as well as a more Rust-friendly interface.

[Check out the documentation for usage information.](http://rust-ci.org/erik/knuckle/doc/knuckle/)

## License

The MIT License (MIT)

Copyright (c) 2014 Erik Price

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
