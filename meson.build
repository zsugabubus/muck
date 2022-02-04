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

cover = custom_target(
	'Cover',
	input: 'cover.png',
	output: 'cover.png.h',
	command: ['cover.gen', '@INPUT0@', '@OUTPUT@'],
)

executable('muck',
	'muck.c', 'rnd.c', cover,
	dependencies: [
		ffmpeg_dep,
		icu_dep,
		dependency('ncursesw'),
		dependency('libpcre2-8'),
	],
	install: true,
)

install_man('muck.1')

install_data('muck_playlist.py',
	rename: 'muck-playlist',
	install_mode: 'r-xr-xr-x',
	install_dir: get_option('bindir')
)
test('test muck-playlist', find_program('test_muck_playlist'))
