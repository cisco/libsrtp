# libSRTP fuzzer
if not add_languages('cpp', required: get_option('fuzzer').enabled())
  subdir_done()
endif

cxx = meson.get_compiler('cpp')
if cxx.get_id() != 'clang'
  err_msg = 'libSRTP fuzzer requires compilation with clang, but compiler is ' + cxx.get_id()
  if get_option('fuzzer').enabled()
    error(err_msg)
  else
    warning(err_msg)
    subdir_done()
  endif
endif

libfuzzer = cxx.find_library('libFuzzer', required: get_option('fuzzer'))

# libFuzzer.a seems to need pthread, at least on Linux
threads = dependency('threads')

if libfuzzer.found()
  executable('srtp-fuzzer',
    'fuzzer.c', 'testmem.c', 'mt19937.cpp',
    include_directories: [config_incs, crypto_incs, srtp2_incs],
    cpp_args: ['-fsanitize=fuzzer'],
    override_options : ['cpp_std=c++11'],
    dependencies: [libfuzzer, threads],
    link_with: libsrtp2,
    install: false)
endif
