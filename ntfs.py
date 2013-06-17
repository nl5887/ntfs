#!/usr/bin/env python
#
# ntfs.py
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston,
# MA  02111-1307  USA

# https://github.com/nl5887/nfts

import binascii
import struct
import zlib
import datetime
import uuid
import argparse

def ft(timestamp):
	return (filetime_to_dt(timestamp))

from datetime import datetime, timedelta, tzinfo
from calendar import timegm


# http://support.microsoft.com/kb/167296
# How To Convert a UNIX time_t to a Win32 FILETIME or SYSTEMTIME
EPOCH_AS_FILETIME = 116444736000000000  # January 1, 1970 as MS file time
HUNDREDS_OF_NANOSECONDS = 10000000

ZERO = timedelta(0)
HOUR = timedelta(hours=1)

class UTC(tzinfo):
    """UTC"""
    def utcoffset(self, dt):
        return ZERO

    def tzname(self, dt):
        return "UTC"

    def dst(self, dt):
        return ZERO


utc = UTC()

def dt_to_filetime(dt):
    """Converts a datetime to Microsoft filetime format. If the object is
    time zone-naive, it is forced to UTC before conversion.

    >>> "%.0f" % dt_to_filetime(datetime(2009, 7, 25, 23, 0))
    '128930364000000000'

    >>> "%.0f" % dt_to_filetime(datetime(1970, 1, 1, 0, 0, tzinfo=utc))
    '116444736000000000'

    >>> "%.0f" % dt_to_filetime(datetime(1970, 1, 1, 0, 0))
    '116444736000000000'
    
    >>> dt_to_filetime(datetime(2009, 7, 25, 23, 0, 0, 100))
    128930364000001000
    """
    if (dt.tzinfo is None) or (dt.tzinfo.utcoffset(dt) is None):
        dt = dt.replace(tzinfo=utc)
    ft = EPOCH_AS_FILETIME + (timegm(dt.timetuple()) * HUNDREDS_OF_NANOSECONDS)
    return ft + (dt.microsecond * 10)


def filetime_to_dt(ft):
    """Converts a Microsoft filetime number to a Python datetime. The new
    datetime object is time zone-naive but is equivalent to tzinfo=utc.

    >>> filetime_to_dt(116444736000000000)
    datetime.datetime(1970, 1, 1, 0, 0)

    >>> filetime_to_dt(128930364000000000)
    datetime.datetime(2009, 7, 25, 23, 0)
    
    >>> filetime_to_dt(128930364000001000)
    datetime.datetime(2009, 7, 25, 23, 0, 0, 100)
    """
    # Get seconds and remainder in terms of Unix epoch
    (s, ns100) = divmod(ft - EPOCH_AS_FILETIME, HUNDREDS_OF_NANOSECONDS)
    # Convert to datetime object
    dt = datetime.utcfromtimestamp(s)
    # Add remainder in as microseconds. Python 3.2 requires an integer
    dt = dt.replace(microsecond=(ns100 // 10))
    return dt


timeline = []
tree = {}

def main():
	parser = argparse.ArgumentParser(
		prog='ntfs.py',
		description='ntfs.py extracts MFT records from raw files.',
		formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    
	subparsers = parser.add_subparsers(dest='command')
	parser_a = subparsers.add_parser('timeline', help='order the mft records by timeline')
	parser_a = subparsers.add_parser('dump', help='dump mft records')
	
	parser.add_argument('--input', required=True)
	args = parser.parse_args()
	
	# http://www.diydatarecovery.nl/kb_disk_general_article.htm
	# http://www.ntfs.com/ntfs-partition-boot-sector.htm
	# http://technet.microsoft.com/en-us/library/cc977221.aspx
	with open(args.input, 'rb') as f:
			s = struct.Struct('<3x8s25s48s426x2s')
			oem, bpb, ebpb, marker, = s.unpack_from(f.read(s.size))
			print "OEM: {0} Marker: {1}".format(oem, binascii.hexlify(marker))
			s =  struct.Struct('<HBH3x2xB2xHHL4x')
			bytespersector, sectorspercluster, reservedsectors, mediadescriptor, sectorspertrack, numberofheads, hiddensectors, = s.unpack_from(bpb)
			print s.size
			
			# mediadescriptor: http://stanislavs.org/helppc/media_descriptor_byte.html
			print "{0} {1} {2} {3} {4} {5} {6}".format(bytespersector, sectorspercluster, reservedsectors, mediadescriptor, sectorspertrack, numberofheads, hiddensectors)
	
			s =  struct.Struct('<4xQQQLB3x4sL')
			totalsectors, lcnmft, lcnmftmirr, cpfrs, cpib, serial, checksum, = s.unpack_from(ebpb)
			print "{0} {1} {2} {3} {5} {6}".format(totalsectors, lcnmft, lcnmftmirr, cpfrs, cpib, binascii.hexlify(serial), checksum)
	 
			f.seek(bytespersector * sectorspercluster * lcnmft)		
			i = 0
			
			while True:
				f.seek(bytespersector * sectorspercluster * lcnmft + (i))		
	
				# mft record
				data = f.read(48)
	
				s =  struct.Struct('<4s2x2x8x2x2xHHLL8x2x2xL')
				type, attr_offset, flags, used, allocated, number, = s.unpack_from(data)
				
				if (not type.rstrip(b'\x00')):
					break
				
				# read complete record	
				f.seek(bytespersector * sectorspercluster * lcnmft + (i))		
				
				data = f.read(allocated)
				
				print "Type {0} Allocated {1} Used {2} Number {3} Flags {4}".format(type, allocated, used, number, flags)
				
				is_inuse = flags & 0x1
				is_directorry = flags & 0x2
				
				"""
				Flags:
				
				0x01	Record is in use
				0x02	Record is a directory
				0x04	Don't know
				0x08	Don't know
				"""
	
				data = data[attr_offset:]
				
				attribute_types = {
					0x10: 'Standard Information',
					0x20: 'Attribute List',
					0x30: 'File Name',
					0x40: 'Object ID',
					0x50: 'Security Descriptor',
					0x60: 'Volume Name',
					0x70: 'Volume Information',
					0x80: 'Data',
					0x90: 'Index Root',
					0xA0: 'Index Allocation',
					0xB0: 'Bitmap',
					0xC0: 'Reparse Point',
					0x100: 'Logged Tool Stream',
					0xFFFFFFFF: 'End',
				}
				
				# http://www.opensource.apple.com/source/ntfs/ntfs-80/kext/ntfs_layout.h
				while type!=0xFFFFFFFF:
					# attribute record header
					s =  struct.Struct('<LH2xBBHHH')
					type, length, form_code, name_length, name_offset, flags, attrib_id = s.unpack_from(data)
			
					if ('timeline' == args.command):
						print "Attribute: type {0} length {1} form {2} name offset {3} length {4} flags {5} attribid {6}".format(attribute_types[type], length, form_code, name_offset, name_length, flags, attrib_id)
	
					#print binascii.hexlify(data[:length]) 
					#print len(data[:length]) 
	
					if (form_code==0x00):
						# resident
						s = struct.Struct('<LH2x')
						content_length, content_offset, = s.unpack_from(data[16:])
						print "length: {0} offset: {1}".format(content_length, content_offset)
	
						# $STANDARD
						if (type==0x10):
							s = struct.Struct('<QQQQ')
							#s = struct.Struct('<4xQQQQQQ4xBB')
							date_created, date_modified, date_mft_modified, date_accessed, = s.unpack_from(data[content_offset:content_offset+content_length])
							if ('dump' == args.command):
								print "$STANDARD: date_created {1} ({2}), date_modified {3} ({4}), date_mft_modified {5} ({6}), date_accessed {7} ({8})".format("", ft(date_created), date_created, ft(date_modified), date_modified, ft(date_mft_modified), date_mft_modified, ft(date_accessed), date_accessed, )
	
						if (type==0x30):
							s = struct.Struct('<QQQQQQQL4xBB')
							#s = struct.Struct('<4xQQQQQQ4xBB')
							parent_directory, date_created, date_modified, date_mft_modified, date_accessed, logical_size, data_size, flags, name_len, name_type, = s.unpack_from(data[content_offset:content_offset+content_length])
							filename = data[content_offset+0x42:content_offset+0x42+name_len*2]
							if ('dump' == args.command):
								print "FILENAME: logical_size {4}, data_size {3}, name_len {0}, name_type {1}, {2} date_created {5} ({6}), date_modified {7} ({8}), date_mft_modified {9} ({10}), date_accessed {11} ({12}) parent_directory: {13} flags: {14}".format(name_len, name_type, filename, logical_size, data_size, ft(date_created), date_created, ft(date_modified), date_modified, ft(date_mft_modified), date_mft_modified, ft(date_accessed), date_accessed, parent_directory, flags,)
								print "FILENAME: {0}  PARENT: {1}".format(data[content_offset+0x42:content_offset+0x42+name_len*2], parent_directory)
							#logical_size, data_size, name_len, name_type, = s.unpack_from(data[content_offset:content_offset+content_length])
							#print "FILENAME: logical_size {4}, data_size {3}, name_len {0}, name_type {1}, {2} ".format(name_len, name_type, data[content_offset+0x42:content_offset+0x42+name_len*2], logical_size, data_size, )
							# parent_directory = parent_directory & 
							# 0x10000000 -> directory
							tree[number]=filename
							
							if (not is_inuse):
								filename = filename + "*"
	
							if ((parent_directory & 0xFFFFFFFF) in tree):
								filename = "{0}\{1}".format(tree[parent_directory & 0xFFFFFFFF], filename)
							
							timeline.append((date_created,"{0} created (0x30)".format(filename)))
							timeline.append((date_modified,"{0} modified (0x30)".format(filename)))
							timeline.append((date_mft_modified,"{0} mft modified (0x30)".format(filename)))
							timeline.append((date_accessed,"{0} accessed (0x30)".format(filename)))
	
						if (type==0x40):
							s = struct.Struct('<16s')
							objectid, = s.unpack_from(data[content_offset:content_offset+content_length]);
							if ('dump' == args.command):
								print "Object Id: {0}".format(uuid.UUID(bytes = objectid).hex, )
						if (type==0x80):
							if ('dump' == args.command):
								print "DATA: {0}".format(data[content_offset:content_offset+content_length], )
	
						data = data[length:]
						pass
					elif (form_code==0x01):
						# non resident
						s = struct.Struct('<QQHH4xQQQ16x')
						svcn, evcn, mpo, cus, sac, sdac, isac, = s.unpack_from(data[16:])
						print "{0} {1} {2} {3} {4} {5} {6}".format(svcn, evcn, mpo, cus, sac, sdac, isac,)
						data = data[length:]
						pass
						
						
	
							
				i = i + allocated
			
			if ('timeline' == args.command):
				for v in sorted(timeline, key=lambda t: t[0]):
					print "{0} {1}".format(ft(v[0]), v[1])
				
if __name__ == "__main__":
    main()			