# test helpers
ADD_LIBRARY(test_helpers gpg_helper.cpp temporary_directory.cpp)
TARGET_LINK_LIBRARIES(test_helpers asymmetric boost_filesystem boost_system)

# test helper tests
ADD_EXECUTABLE(test_gpg_helper test_gpg_helper.cpp)
TARGET_LINK_LIBRARIES(test_gpg_helper gtest gtest_main test_helpers)

ADD_TEST(NAME RUNNER_test_gpg_helper COMMAND "$<TARGET_FILE:test_gpg_helper>")
ADD_TEST(NAME VRUNNER_test_gpg_helper COMMAND valgrind --error-exitcode=1
    --leak-check=full --suppressions=${CMAKE_SOURCE_DIR}/valgrind.suppressions "$<TARGET_FILE:test_gpg_helper>")

ADD_EXECUTABLE(test_temporary_directory test_temporary_directory.cpp)
TARGET_LINK_LIBRARIES(test_temporary_directory gtest gtest_main test_helpers)

ADD_TEST(NAME RUNNER_test_temporary_directory COMMAND "$<TARGET_FILE:test_temporary_directory>")
ADD_TEST(NAME VRUNNER_test_temporary_directory COMMAND valgrind --error-exitcode=1
    --leak-check=full --suppressions=${CMAKE_SOURCE_DIR}/valgrind.suppressions "$<TARGET_FILE:test_temporary_directory>")

# gpg_recipient tests
ADD_EXECUTABLE(test_gpg_recipient test_gpg_recipient.cpp)
TARGET_LINK_LIBRARIES(test_gpg_recipient gtest gtest_main asymmetric)

ADD_TEST(NAME RUNNER_test_gpg_recipient COMMAND "$<TARGET_FILE:test_gpg_recipient>")
ADD_TEST(NAME VRUNNER_test_gpg_recipient COMMAND valgrind --error-exitcode=1
    --leak-check=full --suppressions=${CMAKE_SOURCE_DIR}/valgrind.suppressions "$<TARGET_FILE:test_gpg_recipient>")

# implementation tests
ADD_EXECUTABLE(test_implementation test_implementation.cpp)
TARGET_LINK_LIBRARIES(test_implementation gtest gtest_main asymmetric test_helpers)

ADD_TEST(NAME RUNNER_test_implementation COMMAND "$<TARGET_FILE:test_implementation>")
ADD_TEST(NAME VRUNNER_test_implementation COMMAND valgrind --error-exitcode=1
    --leak-check=full --suppressions=${CMAKE_SOURCE_DIR}/valgrind.suppressions "$<TARGET_FILE:test_implementation>")

# page_buffer tests
ADD_EXECUTABLE(test_page_buffer test_page_buffer.cpp)
TARGET_LINK_LIBRARIES(test_page_buffer gtest asymmetric)

ADD_TEST(NAME RUNNER_test_page_buffer COMMAND "$<TARGET_FILE:test_page_buffer>")
ADD_TEST(NAME VRUNNER_test_page_buffer COMMAND valgrind --error-exitcode=1
    --leak-check=full --suppressions=${CMAKE_SOURCE_DIR}/valgrind.suppressions "$<TARGET_FILE:test_page_buffer>")

# subprocess tests
ADD_EXECUTABLE(test_subprocess test_subprocess.cpp)
TARGET_LINK_LIBRARIES(test_subprocess gtest gtest_main asymmetric)

ADD_TEST(NAME RUNNER_test_subprocess COMMAND "$<TARGET_FILE:test_subprocess>")
ADD_TEST(NAME VRUNNER_test_subprocess COMMAND valgrind --error-exitcode=1
    --leak-check=full --suppressions=${CMAKE_SOURCE_DIR}/valgrind.suppressions "$<TARGET_FILE:test_subprocess>")
