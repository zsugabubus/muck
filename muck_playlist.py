#!/usr/bin/env python3

import glob
import sys
from io import StringIO
from os import rename, unlink
from os.path import basename, dirname, join, isabs, isfile, normpath, relpath, splitext
from re import fullmatch, IGNORECASE
from subprocess import DEVNULL, PIPE, Popen
from tempfile import NamedTemporaryFile

class Playlist:
	COMPRESSORS = {
		'.bz': 'bzip2',
		'.bz2': 'bzip2',
		'.gz': 'gzip',
		'.lz4': 'lz4',
		'.xz': 'xz',
		'.zst': 'zstd',
	}
	IGNORE_PATTERN = r'\..*|.*\.m3u8?(\.[a-z0-9]*)?|cover\.[a-z0-9]*|.*\.(je?pg|png|tiff)'

	def __init__(self, *, basedir='.', entries=[], name=None):
		self.basedir = basedir
		self.entries = entries
		self.name = name

	@classmethod
	def read_dir(cls, /, dir):
		return cls(
			basedir=dir,
			entries=[
				PlaylistEntry(url=f)
				for f in glob.iglob('**', recursive=True)
				if isfile(f) and not fullmatch(
					cls.IGNORE_PATTERN,
					basename(f),
					flags=IGNORECASE,
				)
			],
		)

	@classmethod
	def read_m3u(cls, /, f):
		close_stream = None

		try:
			proc = None
			if isinstance(f, str):
				basedir = dirname(f)
				(root, ext) = splitext(f)
				if compressor := cls.COMPRESSORS.get(ext, None):
					with open(f, 'r') as inf:
						proc = Popen(
							[compressor, '-d'],
							stdin=inf,
							stdout=PIPE,
							stderr=DEVNULL,
						)
						f = proc.stdout
				else:
					f = close_stream = open(f, 'r')
			else:
				try:
					basedir = dirname(f.name)
				except AttributeError:
					basedir = '.'

			entries = []
			name = None
			extinf = None
			for line in f:
				if isinstance(line, bytes):
					line = line.decode('utf-8')
				line = line.rstrip('\r\n')
				if line.startswith('#'):
					if line.startswith('#EXTINF:'):
						extinf = line[8:]
					elif line.startswith('#PLAYLIST:'):
						name = line[10:]
				else:
					entries.append(PlaylistEntry(
						url=normpath(line),
						extinf=extinf,
					))
					extinf = None

			if proc:
				proc.wait()
				if proc.returncode:
					raise RuntimeError('Decompressor process terminated with error')
		finally:
			if close_stream:
				close_stream.close()

		return cls(
			basedir=basedir,
			entries=entries,
			name=name,
		)

	def save(self, f):
		if not isinstance(f, str):
			self.write(f)
			return

		with NamedTemporaryFile(
			dir=dirname(f),
			delete=False,
		) as tmpf:
			try:
				(root, ext) = splitext(f)
				proc = None
				if compressor := self.COMPRESSORS.get(ext, None):
					proc = Popen(
						[compressor, '-c'],
						stdin=PIPE,
						stdout=tmpf,
						stderr=DEVNULL,
					)
					stream = proc.stdin
				else:
					stream = tmpf
				self.write(stream)
				stream.close()
				if proc:
					proc.wait()
					if proc.returncode:
						raise RuntimeError('Compressor process terminated with error')
				rename(tmpf.name, f)
				tmpf = None
			finally:
				if tmpf:
					unlink(tmpf.name)

	def write(self, /, f):
		f.write(b'#EXTM3U\n')
		if self.name:
			f.write(b'#PLAYLIST:%s\n' % self.name.encode('utf-8'))

		for entry in self.entries:
			if entry.extinf:
				f.write(b'#EXTINF:')
				f.write(entry.extinf.encode('utf-8'))
				f.write(b'\n')
			url = entry.url
			if entry.is_file() and not isabs(url):
				if url[0] == '#':
					url = './' + url
			f.write(url.encode('utf-8'))
			f.write(b'\n')

	def update_extinf(self, playlists):
		if not playlists:
			return

		lookup = {}
		for entry in self.entries:
			lookup[entry.url] = entry

		for playlist in playlists:
			for src in playlist.entries:
				if not src.extinf:
					continue
				if src.is_file():
					url = join(playlist.basedir, src.url)
					if not isabs(url):
						url = relpath(url, self.basedir)
				else:
					url = src.url
				if dest := lookup.get(url, None):
					dest.extinf = src.extinf

	def extend(self, playlist):
		self.entries.extend(playlist.entries)

class PlaylistEntry:
	__slots__ = 'url', 'extinf'

	def __init__(self, url, extinf=None):
		self.url = url
		self.extinf = extinf

	def is_file(self):
		return not '://' in self.url

	def __eq__(self, other):
		return self.url == other.url and \
		       self.extinf == other.extinf

	def __repr__(self):
		return f'{self.url} (EXTINF:{self.extinf or "(none)"})'

if __name__ == '__main__':
	import argparse

	default_basename = 'playlist.m3u8'
	default_name = glob.glob(glob.escape(default_basename) + '*')
	if len(default_name) == 1:
		default_name = default_name[0]
	else:
		default_name = default_basename

	parser = argparse.ArgumentParser(
		description="maintain M3U music database",
	)
	parser.add_argument('-i', '--input', nargs='+',
		default=[],
		help='playlists to gather files from')
	parser.add_argument('-d', '--dir', nargs='+',
		default=[],
		help='directories to gather files from (default unless INPUT specified: .)')
	parser.add_argument('-p', '--playlist', nargs='*',
		default=[default_name],
		help='playlists to take metadata from (default: %s (auto))' % default_name)
	parser.add_argument('-o', '--output',
		help='output playlist (default: first PLAYLIST)')

	args = parser.parse_args()
	if args.output is None:
		if args.playlist:
			args.output = args.playlist[0]
		else:
			args.output = '-'
	if not args.input:
		args.dir = ['.']

	playlist = Playlist()
	for f in args.input:
		playlist.extend(Playlist.read_m3u(sys.stdin.buffer if f == '-' else f))
	for dir in args.dir:
		playlist.extend(Playlist.read_dir(dir))
	playlists = [
		Playlist.read_m3u(sys.stdin.buffer if playlist == '-' else playlist)
		for playlist in args.playlist
	]
	if playlists:
		playlist.name = playlists[0].name
	playlist.update_extinf(playlists)
	playlist.save(sys.stdout.buffer if args.output == '-' else args.output)
