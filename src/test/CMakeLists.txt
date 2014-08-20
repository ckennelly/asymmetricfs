# page_buffer tests
ADD_EXECUTABLE(test_page_buffer test_page_buffer.cpp)
TARGET_LINK_LIBRARIES(test_page_buffer gtest asymmetric)

ADD_TEST(NAME RUNNER_test_page_buffer COMMAND "$<TARGET_FILE:test_page_buffer>")
ADD_TEST(NAME VRUNNER_test_page_buffer COMMAND valgrind --error-exitcode=1 --leak-check=full "$<TARGET_FILE:test_page_buffer>")

# subprocess tests
ADD_EXECUTABLE(test_subprocess test_subprocess.cpp)
TARGET_LINK_LIBRARIES(test_subprocess gtest gtest_main asymmetric)

ADD_TEST(NAME RUNNER_test_subprocess COMMAND "$<TARGET_FILE:test_subprocess>")
ADD_TEST(NAME VRUNNER_test_subprocess COMMAND valgrind --error-exitcode=1 --leak-check=full "$<TARGET_FILE:test_subprocess>")
