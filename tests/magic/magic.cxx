#include <magic/magic.hxx>

TEST_F(MagicTest, MagicLoadMime)
{
    std::string test_string = "the best engine";

    magic->load_mime(test_string);
    std::string mime_type = magic->mime;

    ASSERT_EQ("text/plain; charset=us-ascii", mime_type);
}
