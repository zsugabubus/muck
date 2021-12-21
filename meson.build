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

cc = meson.get_compiler('c')

ffmpeg_dir = meson.source_root() / 'ffmpeg'
ffmpeg_link_args = []
foreach lib: ['swresample', 'swscale', 'avcodec', 'avdevice', 'avformat', 'avutil', 'avfilter']
	ffmpeg_link_args += [
		'-L' + ffmpeg_dir / 'lib' + lib / '',
		'-l' + lib,
	]
endforeach
ffmpeg_dep = declare_dependency(
	link_args: ffmpeg_link_args + ['-lstdc++'],
	compile_args: ['-isystem', ffmpeg_dir],
	dependencies: [

		cc.find_library('dl'),
		cc.find_library('m'),
		dependency('alsa'),
		dependency('bzip2'),
		dependency('libva-drm'),
		dependency('libva-x11'),
		dependency('libxml-2.0'),
		dependency('openssl'),
		dependency('opus'),
		dependency('threads'),
		dependency('vdpau'),
		dependency('x11'),
		dependency('zlib'),
		dependency('ncursesw'),
		dependency('libpcre2-8'),

	],
)

config = configuration_data()
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
	],
	install: true,
)

install_man('muck.1')
