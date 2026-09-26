#pragma once

struct Header {
    unsigned length;
    unsigned flags;
};

class Decoder {
public:
    int decode(const Header &header);
private:
    unsigned offset_;
};

using DecodeFn = int (*)(const Header &);

inline unsigned header_length(const Header &header) {
    return header.length;
}
