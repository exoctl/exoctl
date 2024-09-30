#include <magic/magic.hxx>

TEST_F(MagicTest, MagicLoadMime)
{
    std::string test_string = "the best engine";

    magic->magic_load_mime(test_string);
    std::string mime_type = magic->magic_get_mime();

    ASSERT_EQ("text/plain; charset=us-ascii", mime_type);
}
