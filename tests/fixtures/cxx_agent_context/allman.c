#include <stdlib.h>

namespace runtime {

extern "C" int scale_value(int value, int factor)
{
    return value * factor;
}

int *make_scaled(int count, int factor)
{
    int *buffer = malloc(sizeof(int) * count);
    if (buffer != NULL)
    {
        for (int index = 0; index < count; ++index)
        {
            buffer[index] = scale_value(index, factor);
        }
    }
    return buffer;
}

}
