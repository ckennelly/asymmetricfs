# page_buffer tests
ADD_EXECUTABLE(test_page_buffer test_page_buffer.cpp)
TARGET_LINK_LIBRARIES(test_page_buffer gtest asymmetric)

ADD_TEST(NAME RUNNER_test_page_buffer COMMAND "$<TARGET_FILE:test_page_buffer>")
ADD_TEST(NAME VRUNNER_test_page_buffer COMMAND valgrind --error-exitcode=1 --leak-check=full "$<TARGET_FILE:test_page_buffer>")
