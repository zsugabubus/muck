project('muck', 'c',
	version: run_command(
		'git describe --always --tags --dirty --match v*'.split(' ')
	).stdout().strip(),
	default_options: [
		'c_std=c11',
		'warning_level=2',
	]
)

add_project_arguments([
	'-D_DEFAULT_SOURCE',
	'-D_GNU_SOURCE',
	'-D_XOPEN_SOURCE=700',
	'-DMUCK_VERSION="@0@ @1@"'.format(
		meson.project_name(),
		meson.project_version(),
	),
], language: 'c')

ffmpeg_dep = declare_dependency(
	dependencies: [
		dependency('libavcodec'),
		dependency('libavdevice'),
		dependency('libavformat'),
		dependency('libavutil'),
		dependency('libavfilter'),
	],
)

icu_dep = dependency('icu-i18n', required: get_option('unicode'))

config = configuration_data()
cc = meson.get_compiler('c')

foreach fn: ['pthread_setname_np']
	config.set10('HAVE_' + fn.to_upper(), cc.has_function(
		fn,
		prefix: '#define _GNU_SOURCE\n#include <pthread.h>',
		dependencies: [dependency('threads')]
	))
endforeach

foreach fn: ['__builtin_expect']
	config.set10('HAVE_' + fn.to_upper(), cc.has_function(fn))
endforeach

foreach fn: ['strchrnul']
	config.set10('HAVE_' + fn.to_upper(), cc.has_function(
		fn,
		prefix: '#define _GNU_SOURCE\n#include <string.h>',
	))
endforeach

config.set10('CONFIG_VALGRIND', get_option('buildtype').contains('debug'))

config.set10('WITH_ICU', icu_dep.found())

configure_file(output: 'config.h', configuration: config)

# Image was taken from https://github.com/mathiasbynens/small.
cover = custom_target(
	'default cover',
	input: 'cover.png',
	output: 'cover.h',
	command: ['hexdump', '-ve', '/1 "%u,"', '--', '@INPUT0@'],
	capture: true,
)

muck_deps = [
	ffmpeg_dep,
	icu_dep,
	dependency('ncursesw'),
	dependency('libpcre2-8'),
]

src = [
	'fdata.c',
	'file.c',
	'files.c',
	'files_par.c',
	'player.c',
	'playlist.c',
	'tmpf.c',
	'rnd.c',
	'env.c',
	'error.c',
	'tui.c',
	'expr.c',

]

executable('muck',
	'muck.c',
	src,
	cover,
	dependencies: muck_deps,
	install: true,
)

install_man('muck.1')

install_data('muck_playlist.py',
	rename: 'muck-playlist',
	install_mode: 'r-xr-xr-x',
	install_dir: get_option('bindir')
)

test_env = [
	'BUILD_ROOT=' + meson.build_root(),
	'WORK_ROOT=' + meson.build_root() / 'test',
]

test('unit',
	executable('unit_test',
		'test/unit_test.c',
		src,
		dependencies: muck_deps
	),
	is_parallel: false,
)
test('functional', find_program('test/functional_test'), env: test_env)
test('functional_long', find_program('test/functional_test_long'), env: test_env)
test('muck-playlist', find_program('test/test_muck_playlist'),
	env: [
		'PYTHONPATH=' + meson.source_root() + ':',
	],
)
