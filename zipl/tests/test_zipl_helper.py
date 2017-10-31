import io
import sys
import unittest
import unittest.mock as mock
import src.zipl_helper as dm
from random import randint
from collections import defaultdict
from subprocess import CompletedProcess, CalledProcessError


@mock.patch('builtins.open', new_callable=mock.mock_open())
class TestGetDeviceName(unittest.TestCase):
    def setUp(self):
        self.partitions = io.StringIO(
"""
major minor  #blocks  name

   8        0  250059096 sda
   8        1    1048576 sda1
   8        2  249009152 sda2
   253      0  249007104 dm-0
   253      1   52428800 dm-1
   253      2    6066176 dm-2
   253      3  190509056 dm-3
""")

    def test_get_device_name(self, m):
        m.return_value.__enter__.return_value = self.partitions
        l = zip([(8, 0), (8, 1), (8, 2), (253, 0), (253, 1), (253, 2), (253, 3)],
                ['sda', 'sda1', 'sda2', 'dm-0', 'dm-1', 'dm-2', 'dm-3'])

        for (major, minor), name in l:
            with self.subTest(major=major, minor=minor, name=name):
                self.assertEqual(name, dm.get_device_name(major, minor))
        m.assert_any_call('/proc/partitions', 'r')

    def test_get_device_name_not_in_file(self, m):
        m.return_value.__enter__.return_value = self.partitions
        self.assertEqual('9:0', dm.get_device_name(9, 0))

    def test_get_device_name_empty_file(self, m):
        m.return_value.__enter__.return_value = ''
        self.assertEqual('9:1', dm.get_device_name(9, 1))


class TestLinearData(unittest.TestCase):
    def setUp(self):
        self.devname = '/boot-new'
        self.major = randint(0, 255)
        self.minor = randint(0, 255)
        self.start = randint(0, sys.maxsize)

    def test_get_linear_data(self):
        args = '{}:{} {}'.format(self.major, self.minor, self.start)
        expected = dm.TargetData(self.major, self.minor, self.start)
        self.assertEqual(expected, dm.get_linear_data(self.devname, args))

    def test_get_linear_data_extra_sep_spaces(self):
        expected = dm.TargetData(self.major, self.minor, self.start)
        for i in range(2, 10):
            args = '{}:{}{}{}'.format(self.major, self.minor, ' ' * i, self.start)
            with self.subTest(i=i):
                res = dm.get_linear_data(self.devname, args)
                self.assertEqual(expected, res)

    def test_get_linear_data_fails(self):
        args = '{}:{} {}'.format(self.major + 1, self.minor + 1, self.start + 1)
        expected = dm.TargetData(self.major, self.minor, self.start)
        res = dm.get_linear_data(self.devname, args)
        self.assertNotEqual(expected, res)

    def test_get_linear_data_extra_invalid_spaces(self):
        args = '  {}: {}  {}'
        with self.assertRaises(SystemExit) as se:
            dm.get_linear_data(self.devname, args)
        self.assertEqual(se.exception.code, 1)

    def test_get_linear_data_invalid_input(self):
        invalids = ['', ' ', ':', ': 1', '10: 1', ':2 1', '10:2', '1:', ':1',
                    'invalid', 'invalid:invalid', 'invalid:invalid invalid',
                    '10:2 A', 'A:2 3', '10:B 3', 'A:B 3', 'A:B C',
                    '1.0:3 4', '10:1.2 3', '10:2 1.2', '1.0:1.1 1', '1.0:1.1 1.2']
        for invalid in invalids:
            with self.subTest(invalid=invalid):
                with self.assertRaises(SystemExit) as se:
                    dm.get_linear_data(self.devname, invalid)
                self.assertEqual(se.exception.code, 1)


class TestMirrorData(unittest.TestCase):
    def setUp(self):
        self.devname = '/boot-new'
        self.table_msg = dm.UNRECOG_TABLE_MSG % self.devname

    def test_get_mirror_data_single_dev(self):
        args = 'log_type 1 log_arg 1 9:1 0 1 feature1'
        res = dm.get_mirror_data(self.devname, args)
        self.assertEqual(res, [dm.TargetData(9, 1, 0)])

    def test_get_mirror_data_multiple_devs(self):
        args = 'log_type 1 log_arg 2 9:1 0 9:2 0 1 feature1'
        res = dm.get_mirror_data(self.devname, args)
        self.assertEqual(res,
                        [dm.TargetData(9, 1, 0), dm.TargetData(9, 2, 0)])

    def test_get_mirror_data_multiple_features(self):
        args = 'log_type 1 log_arg 1 9:1 0 3 feat1 feat2 feat3'
        res = dm.get_mirror_data(self.devname, args)
        self.assertEqual(res, [dm.TargetData(9, 1, 0)])

    def test_get_mirror_data_no_features(self):
        args = 'log_type 1 log_arg 1 9:1 0 0'
        res = dm.get_mirror_data(self.devname, args)
        self.assertEqual(res, [dm.TargetData(9, 1, 0)])

    def test_get_mirror_data_multiple_log_args(self):
        args = 'log_type 3 log_arg1 log_arg2 log_arg3 1 9:1 0 1 feat1'
        res = dm.get_mirror_data(self.devname, args)
        self.assertEqual(res, [dm.TargetData(9, 1, 0)])

    def test_get_mirror_data_no_log_args(self):
        args = 'log_type 0 1 9:1 0 1 feat1'
        res = dm.get_mirror_data(self.devname, args)
        self.assertEqual(res, [dm.TargetData(9, 1, 0)])

    def test_get_mirror_data_no_devs(self):
        args = 'log_type 0 0 1 feat1'
        res = dm.get_mirror_data(self.devname, args)
        self.assertEqual(res, [])

    def test_get_mirror_data_varying_offset(self):
        args = 'log_type 1 log_arg 2 9:1 0 9:2 1 1 feature1'
        with self.assertLogs(level='CRITICAL') as cm:
            with self.assertRaises(SystemExit) as se:
                dm.get_mirror_data(self.devname, args)
            self.assertEqual(se.exception.code, 1)
        self.assertEqual(cm.output,
                        ["CRITICAL:src.zipl_helper:Unsupported setup: Mirror "
                        "target on device '%s' contains entries with varying "
                        "sector offsets" % self.devname])

    def test_get_mirror_data_invalid_name(self):
        args = 'log_type 1 log_arg 1 dev 0 1 feature1'
        with self.assertLogs(level='CRITICAL') as cm:
            with self.assertRaises(SystemExit) as se:
                dm.get_mirror_data(self.devname, args)
            self.assertEqual(se.exception.code, 1)
        self.assertEqual(cm.output,
                        ["CRITICAL:src.zipl_helper:%s" % self.table_msg])

    def test_get_mirror_data_truncated_features(self):
        args = 'log_type 1 log_arg 1 9:1 0 2 feature1'
        with self.assertLogs(level='CRITICAL') as cm:
            with self.assertRaises(SystemExit) as se:
                dm.get_mirror_data(self.devname, args)
            self.assertEqual(se.exception.code, 1)
        self.assertEqual(cm.output,
                        ["CRITICAL:src.zipl_helper:%s" % self.table_msg])

    def test_get_mirror_data_truncated_devs(self):
        args = 'log_type 1 log_arg 1 9:1 1 feature1'
        with self.assertLogs(level='CRITICAL') as cm:
            with self.assertRaises(SystemExit) as se:
                dm.get_mirror_data(self.devname, args)
            self.assertEqual(se.exception.code, 1)
        self.assertEqual(cm.output,
                        ["CRITICAL:src.zipl_helper:%s" % self.table_msg])


@mock.patch('src.zipl_helper.run_proc')
class TestMultipathStatus(unittest.TestCase):
    def setUp(self):
        self.devname = '/boot-new'

    def test_get_multipath_status(self, run_mock):
        expected = {'8:16': 'A', '8:0': 'A', '8:32': 'A', '8:48': 'A'}
        run_mock.return_value = CompletedProcess('', 0,
                stdout='0 67108864 multipath 2 0 0 0 2 2 E 0 2 2 8:16 A 1 0 1 8:0 A 1 0 1 A 0 2 2 8:32 A 0 0 1 8:48 A 0 0 1')
        self.assertEqual(dm.get_multipath_status(self.devname), expected)

    def test_get_multipath_status_2(self, run_mock):
        expected = {'8:64': 'A', '8:32': 'A'}
        run_mock.return_value = CompletedProcess('', 0,
                stdout='0 20981760 multipath 2 0 0 0 2 1 A 0 1 2 8:64 A 0 0 1 E 0 1 2 8:32 A 0 0 1')
        self.assertEqual(dm.get_multipath_status(self.devname), expected)

    def test_get_multipath_status_some_failed_warning(self, run_mock):
        expected = {'8:16': 'F', '8:0': 'F', '8:32': 'A', '8:48': 'A'}
        run_mock.return_value = CompletedProcess('', 0,
                stdout='0 67108864 multipath 2 0 0 0 2 2 E 0 2 2 8:16 F 1 0 1 8:0 F 1 0 1 A 0 2 2 8:32 A 0 0 1 8:48 A 0 0 1')

        with self.assertLogs(level='WARNING') as cm:
            dm.get_multipath_status(self.devname)
            self.assertEqual(cm.output,
                            ["WARNING:src.zipl_helper:There are one or more "
                            "failed paths for device '%s'" % self.devname])

    def test_get_multipath_status_all_failed_critical(self, run_mock):
        #expected = {'8:16': 'F', '8:0': 'F', '8:32': 'F', '8:48': 'F'}
        run_mock.return_value = CompletedProcess('', 0,
                stdout='0 67108864 multipath 2 0 0 0 2 2 E 0 2 2 8:16 F 1 0 1 8:0 F 1 0 1 F 0 2 2 8:32 F 0 0 1 8:48 F 0 0 1')
        with self.assertLogs(level='CRITICAL') as cm:
            with self.assertRaises(SystemExit) as se:
                dm.get_multipath_status(self.devname)
            self.assertEqual(se.exception.code, 1)
        self.assertEqual(cm.output,
                        ["CRITICAL:src.zipl_helper:All paths for '%s' failed" %
                        self.devname])

    def test_get_multipath_status_empty_critical(self, run_mock):
        run_mock.return_value = CompletedProcess('', 0, stdout='')
        with self.assertLogs(level='CRITICAL') as cm:
            with self.assertRaises(SystemExit) as se:
                dm.get_multipath_status(self.devname)
            self.assertEqual(se.exception.code, 1)
        self.assertEqual(cm.output,
                        ["CRITICAL:src.zipl_helper:No paths found for '%s'" %
                        self.devname])

    def test_get_multipath_status_no_paths_critical(self, run_mock):
        run_mock.return_value = CompletedProcess('', 0,
                stdout='0 67108864 multipath 2 0 0 0 2 2 E 0 0 0')
        with self.assertLogs(level='CRITICAL') as cm:
            with self.assertRaises(SystemExit) as se:
                dm.get_multipath_status(self.devname)
            self.assertEqual(se.exception.code, 1)
        self.assertEqual(cm.output,
                        ["CRITICAL:src.zipl_helper:No paths found for '%s'" %
                        self.devname])

    def test_get_multipath_status_truncated_input_critical(self, run_mock):
        run_mock.return_value = CompletedProcess('', 0,
                stdout='0 67108864 multipath 2 0 0 0 2 2 E 0 2 2')
        with self.assertLogs(level='CRITICAL') as cm:
            with self.assertRaises(SystemExit) as se:
                dm.get_multipath_status(self.devname)
            self.assertEqual(se.exception.code, 1)
        self.assertEqual(cm.output,
                        ["CRITICAL:src.zipl_helper:No paths found for '%s'" %
                        self.devname])

    def test_get_multipath_status_dmsetup_failed_critical(self, run_mock):
        run_mock.side_effect = CalledProcessError(1, 'dmsetup')
        with self.assertLogs(level='CRITICAL') as cm:
            with self.assertRaises(SystemExit) as se:
                dm.get_multipath_status(self.devname)
            self.assertEqual(se.exception.code, 1)
        self.assertEqual(cm.output,
                        ["CRITICAL:src.zipl_helper:No paths found for '%s': "
                        "'dmsetup status' failed" % self.devname])


def constant_factory(value):
    return lambda: value


@mock.patch('src.zipl_helper.get_multipath_status')
class TestMultipathData(unittest.TestCase):

    def setUp(self):
        self.devname = '/boot-new'
        self.critical_msg = dm.UNRECOG_TABLE_MSG % self.devname

    def test_get_multipath_data_no_features(self, status_mock):
        status_mock.return_value = defaultdict(constant_factory('A'))
        args = "0 0 1 1 pref-path 0 1 1 8:16 100"
        expected = [dm.TargetData(8, 16, 0), dm.TargetData(8, 80, 0),
                    dm.TargetData(8, 144, 0), dm.TargetData(8, 208, 0)]

    def test_get_multipath_data_no_handlers(self, status_mock):
        status_mock.return_value = defaultdict(constant_factory('A'))
        args = "1 queue_if_no_path 0 1 1 round-robin 0 2 1 8:0 100 8:16 100"
        expected = [dm.TargetData(8, 0, 0), dm.TargetData(8, 16, 0)]
        self.assertEqual(dm.get_multipath_data(self.devname, args), expected)

    # FIXME: dunno if this is a valid configuration
    #def test_get_multipath_data_no_groups(self, status_mock):
    #    status_mock.return_value = defaultdict(constant_factory('A'))
    #    args = "1 queue_if_no_path 1 handler 0 1 round-robin 0 1 1 8:0 100"
    #    expected = [dm.TargetData(8, 0)]
    #    self.assertEqual(dm.get_multipath_data(self.devname, args), expected)

    def test_get_multipath_data_no_sel_args(self, status_mock):
        status_mock.return_value = defaultdict(constant_factory('A'))
        args = "1 queue_if_no_path 0 1 1 round-robin 0 1 1 8:0 100"
        expected = [dm.TargetData(8, 0, 0)]
        self.assertEqual(dm.get_multipath_data(self.devname, args), expected)

    def test_get_multipath_data_no_path_args(self, status_mock):
        status_mock.return_value = defaultdict(constant_factory('A'))
        args = "1 queue_if_no_path 0 1 1 round-robin 0 2 0 8:0 8:16"
        expected = [dm.TargetData(8, 0, 0), dm.TargetData(8, 16, 0)]
        self.assertEqual(dm.get_multipath_data(self.devname, args), expected)

    def test_get_multipath_data(self, status_mock):
        status_mock.return_value = defaultdict(constant_factory('A'))
        args = "1 queue_if_no_path 0 1 1 round-robin 0 4 1 8:16 100 8:80 100 8:144 100 8:208 100"
        expected = [dm.TargetData(8, 16, 0), dm.TargetData(8, 80, 0),
                    dm.TargetData(8, 144, 0), dm.TargetData(8, 208, 0)]
        self.assertEqual(dm.get_multipath_data(self.devname, args), expected)

    def test_get_multipath_data_multiple_groups(self, status_mock):
        status_mock.return_value = defaultdict(constant_factory('A'))
        args = "0 0 2 1 service-time 0 1 2 8:48 1 1 service-time 0 1 2 8:16 1 1"
        expected = [dm.TargetData(8, 48, 0), dm.TargetData(8, 16, 0)]
        self.assertEqual(dm.get_multipath_data(self.devname, args), expected)

    def test_get_multipath_data_empty_input(self, status_mock):
        with self.assertLogs(level='CRITICAL') as cm:
            with self.assertRaises(SystemExit) as se:
                dm.get_multipath_data(self.devname, '')
            self.assertEqual(se.exception.code, 1)
        self.assertEqual(cm.output,
                        ["CRITICAL:src.zipl_helper:%s" % self.critical_msg])

    def test_get_multipath_data_truncated_input(self, status_mock):
        with self.assertLogs(level='CRITICAL') as cm:
            with self.assertRaises(SystemExit) as se:
                dm.get_multipath_data(self.devname, '0 0 2 1')
            self.assertEqual(se.exception.code, 1)
        self.assertEqual(cm.output,
                        ["CRITICAL:src.zipl_helper:%s" % self.critical_msg])

    def test_get_multipath_data_critical(self, status_mock):
        status_mock.return_value = {}
        with self.assertLogs(level='CRITICAL') as cm:
            with self.assertRaises(SystemExit) as se:
                dm.get_multipath_data(self.devname, '')
            self.assertEqual(se.exception.code, 1)
        self.assertEqual(cm.output,
                        ["CRITICAL:src.zipl_helper:%s" % self.critical_msg])


@mock.patch('src.zipl_helper.run_proc')
@mock.patch('src.zipl_helper.get_device_name')
class TestTable(unittest.TestCase):

    def setUp(self):
        self.devname = '253:1'
        self.critical_msg = dm.UNRECOG_TABLE_MSG % self.devname

    def test_get_table_dmsetup_exception(self, name_mock, run_mock):
        run_mock.side_effect = CalledProcessError(1, 'dmsetup')
        self.assertEqual(dm.get_table(253, 1), [])

    def test_get_table_invalid_type(self, name_mock, run_mock):
        run_mock.return_value = CompletedProcess('', 0,
                stdout='0 1 invalid %s 1' % self.devname)
        name_mock.return_value = self.devname

        with self.assertLogs(level='CRITICAL') as cm:
            with self.assertRaises(SystemExit) as se:
                dm.get_table(253, 1)
            self.assertEqual(se.exception.code, 1)
        self.assertEqual(cm.output,
                        ["CRITICAL:src.zipl_helper:Unrecognized setup: "
                        "Unsupported device-mapper target type '%s' for "
                        "device '%s'" % ('invalid', self.devname)])

    def test_get_table_linear(self, name_mock, run_mock):
        run_mock.return_value = CompletedProcess('', 0,
                stdout='0 104857600 linear %s 393152512' % self.devname)
        data = dm.TargetData(253, 1, 393152512)
        expected = [dm.Target(0, 104857600, 'linear', data)]
        self.assertEqual(dm.get_table(253, 1), expected)

    def test_get_table_linear_invalid_data(self, name_mock, run_mock):
        run_mock.return_value = CompletedProcess('', 0, stdout='0 0 linear 0 0')
        name_mock.return_value = self.devname

        with self.assertLogs(level='CRITICAL') as cm:
            with self.assertRaises(SystemExit) as se:
                dm.get_table(253, 1)
            self.assertEqual(se.exception.code, 1)
        self.assertEqual(cm.output,
                        ["CRITICAL:src.zipl_helper:%s" % self.critical_msg])

    def test_get_table_linear_invalid_input(self, name_mock, run_mock):
        run_mock.return_value = CompletedProcess('', 0,
                stdout='A B linear %s 0' % self.devname)
        name_mock.return_value = self.devname
        with self.assertLogs(level='CRITICAL') as cm:
            with self.assertRaises(SystemExit) as se:
                dm.get_table(253, 1)
            self.assertEqual(se.exception.code, 1)
        self.assertEqual(cm.output,
                        ["CRITICAL:src.zipl_helper:%s" % self.critical_msg])

    def test_get_table_mirror_invalid_input(self, name_mock, run_mock):
        run_mock.return_value = CompletedProcess('', 0,
                stdout='A B mirror %s 0' % self.devname)
        name_mock.return_value = self.devname
        with self.assertLogs(level='CRITICAL') as cm:
            with self.assertRaises(SystemExit) as se:
                dm.get_table(253, 1)
            self.assertEqual(se.exception.code, 1)
        self.assertEqual(cm.output,
                        ["CRITICAL:src.zipl_helper:%s" % self.critical_msg])

    def test_get_table_multipath(self, name_mock, run_mock):
        def run_proc_mock(args):
            if args[1] == 'status':
                return CompletedProcess('', 0,
                        stdout='0 104878080 multipath 2 0 0 0 2 1 A 0 1 2 8:48 A 0 0 1 E 0 1 2 8:16 A 0 0 1')
            elif args[1] == 'table':
                return CompletedProcess('', 0,
                        stdout='0 104878080 multipath 0 0 2 1 service-time 0 1 2 8:48 1 1 service-time 0 1 2 8:16 1 1')
            else:
                return CalledProcessError(1, 'dmsetup')
        name_mock.return_value = self.devname
        run_mock.side_effect = run_proc_mock
        expected = [dm.Target(0, 104878080, 'multipath',
                    [dm.TargetData(8, 48, 0), dm.TargetData(8, 16, 0)])]
        self.assertEqual(dm.get_table(253, 1), expected)


@mock.patch('src.zipl_helper.get_device_name')
@mock.patch('src.zipl_helper.get_table')
class TestPhysicalDevice(unittest.TestCase):

    def setUp(self):
        self.devname = '253:1'

    def test_get_physical_device_empty_table(self, table_mock, name_mock):
        table_mock.return_value = []
        name_mock.return_value = self.devname
        with self.assertLogs(level='CRITICAL') as cm:
            with self.assertRaises(SystemExit) as se:
                dm.get_physical_device(253, 1)
            self.assertEqual(se.exception.code, 1)
        self.assertEqual(cm.output,
                        ["CRITICAL:src.zipl_helper:Could not retrieve "
                        "device-mapper information for device '%s'" %
                        self.devname])

    def test_get_physical_device_multitarget_table(self, table_mock, name_mock):
        table_mock.return_value = [dm.Target(0, 0, 'linear', None),
                dm.Target(1, 1, 'linear', None)]
        with self.assertLogs(level='CRITICAL') as cm:
            with self.assertRaises(SystemExit) as se:
                dm.get_physical_device(253, 1)
            self.assertEqual(se.exception.code, 1)
        self.assertEqual(cm.output,
                        ["CRITICAL:src.zipl_helper:Unsupported setup: "
                        "Directory '%s' is located on a multi-target "
                        "device-mapper device" % None])

    def test_get_physical_device_linear_table(self, table_mock, name_mock):
        data = dm.TargetData(253, 0, 393152512)
        target = dm.Target(253, 0, 'linear', data)
        def cond_get_table(major, minor):
            if (major, minor) == (253, 1):
                return [target]
            else:
                return []

        table_mock.side_effect = cond_get_table
        self.assertEqual(dm.get_physical_device(253, 1),
                (253, 0, 393152765, [(253, 1, target)]))

    def test_get_physical_device_mirror_table(self, table_mock, name_mock):
        data = [dm.TargetData(253, 0, 393152512)]
        target = dm.Target(253, 0, 'mirror', data)
        def cond_get_table(major, minor):
            if (major, minor) == (253, 1):
                return [target]
            else:
                return []
        table_mock.side_effect = cond_get_table
        self.assertEqual(dm.get_physical_device(253, 1),
                (253, 0, 393152765, [(253, 1, target)]))

    def test_get_physical_device_multipath_table(self, table_mock, name_mock):
        data = [dm.TargetData(8, 48, 0)]
        #target = dm.Target(


@mock.patch('src.zipl_helper.run_proc')
class TestDasdInfo(unittest.TestCase):
    def setUp(self):
        self.devname = '/dev/dasde'

    def test_get_dasd_info(self, run_mock):
        run_mock.return_value = CompletedProcess('', 0, stdout="""

--- general DASD information --------------------------------------------------
device node            : /dev/dasde
busid                  : 0.0.0204
type                   : ECKD
device type            : hex 3390  	dec 13200

--- DASD geometry -------------------------------------------------------------
number of cylinders    : hex d0b  	dec 3339
tracks per cylinder    : hex f  	dec 15
blocks per track       : hex c  	dec 12
blocksize              : hex 1000  	dec 4096

--- extended DASD information -------------------------------------------------
real device number     : hex 0  	dec 0
subchannel identifier  : hex 9ff  	dec 2559
CU type  (SenseID)     : hex 3990  	dec 14736
CU model (SenseID)     : hex e9  	dec 233
device type  (SenseID) : hex 3390  	dec 13200
device model (SenseID) : hex a  	dec 10
open count             : hex 3  	dec 3
req_queue_len          : hex 0  	dec 0
chanq_len              : hex 0  	dec 0
status                 : hex 5  	dec 5
label_block            : hex 2  	dec 2
FBA_layout             : hex 0  	dec 0
characteristics_size   : hex 40  	dec 64
confdata_size          : hex 100  	dec 256
format                 : hex 2  	dec 2      	CDL formatted
features               : hex 0  	dec 0      	default

characteristics        : 3990e933 900a5e8c  3ff72024 0d0b000f
                         e000e5a2 05940222  13090674 00000000
                         00000000 00000000  24241502 dfee0001
                         0677080f 007f4800  1f3c0000 00000d0b

configuration_data     : dc010100 f0f0f2f1  f0f7f9f0 f0c9c2d4
                         f7f5f0f0 f0f0f0f0  f0d3f2f5 f9f11413
                         40000004 00000000  00000000 00000d0a
                         00000000 00000000  00000000 00000000
                         d4020000 f0f0f2f1  f0f7f9f3 f1c9c2d4
                         f7f5f0f0 f0f0f0f0  f0d3f2f5 f9f11400
                         d0000000 f0f0f2f1  f0f7f9f3 f1c9c2d4
                         f7f5f0f0 f0f0f0f0  f0d3f2f5 f9f01400
                         f0000001 f0f0f2f1  f0f7f9f0 f0c9c2d4
                         f7f5f0f0 f0f0f0f0  f0d3f2f5 f9f11400
                         00000000 00000000  00000000 00000000
                         00000000 00000000  00000000 00000000
                         00000000 00000000  00000000 00000000
                         00000000 00000000  00000000 00000000
                         80000002 2d001e00  0015003b 00000215
                         0008c013 5a82b5a6  00020000 0000a000
""")
        expected = ('CDL', 3339, 15, 12)
        self.assertEqual(dm.get_dasd_info(self.devname), expected)

    def test_get_dasd_info_missing_sectors(self, run_mock):
        run_mock.return_value = CompletedProcess('', 0, stdout="""

--- general DASD information --------------------------------------------------
device node            : /dev/dasde
type                   : ECKD
device type            : hex 3390  	dec 13200

--- DASD geometry -------------------------------------------------------------
number of cylinders    : hex d0b  	dec 3339
tracks per cylinder    : hex f  	dec 15
blocksize              : hex 1000  	dec 4096

--- extended DASD information -------------------------------------------------
real device number     : hex 0  	dec 0
status                 : hex 5  	dec 5
confdata_size          : hex 100  	dec 256
format                 : hex 2  	dec 2      	CDL formatted
features               : hex 0  	dec 0      	default
""")
        self.assertEqual(dm.get_dasd_info(self.devname), None)

    def test_get_dasd_info_missing_type(self, run_mock):
        run_mock.return_value = CompletedProcess('', 0, stdout="""

--- general DASD information --------------------------------------------------
device node            : /dev/dasde
device type            : hex 3390  	dec 13200

--- DASD geometry -------------------------------------------------------------
number of cylinders    : hex d0b  	dec 3339
tracks per cylinder    : hex f  	dec 15
blocks per track       : hex c  	dec 12
blocksize              : hex 1000  	dec 4096

--- extended DASD information -------------------------------------------------
real device number     : hex 0  	dec 0
status                 : hex 5  	dec 5
confdata_size          : hex 100  	dec 256
format                 : hex 2  	dec 2      	CDL formatted
features               : hex 0  	dec 0      	default
""")
        self.assertEqual(dm.get_dasd_info(self.devname), None)

    def test_get_dasd_info_missing_cylinders(self, run_mock):
        run_mock.return_value = CompletedProcess('', 0, stdout="""

--- general DASD information --------------------------------------------------
device node            : /dev/dasde
type                   : ECKD
device type            : hex 3390  	dec 13200

--- DASD geometry -------------------------------------------------------------
tracks per cylinder    : hex f  	dec 15
blocks per track       : hex c  	dec 12
blocksize              : hex 1000  	dec 4096

--- extended DASD information -------------------------------------------------
real device number     : hex 0  	dec 0
status                 : hex 5  	dec 5
confdata_size          : hex 100  	dec 256
format                 : hex 2  	dec 2      	CDL formatted
features               : hex 0  	dec 0      	default
""")
        self.assertEqual(dm.get_dasd_info(self.devname), None)

    def test_get_dasd_info_missing_heads(self, run_mock):
        run_mock.return_value = CompletedProcess('', 0, stdout="""

--- general DASD information --------------------------------------------------
device node            : /dev/dasde
type                   : ECKD
device type            : hex 3390  	dec 13200

--- DASD geometry -------------------------------------------------------------
number of cylinders    : hex d0b  	dec 3339
blocks per track       : hex c  	dec 12
blocksize              : hex 1000  	dec 4096

--- extended DASD information -------------------------------------------------
real device number     : hex 0  	dec 0
status                 : hex 5  	dec 5
confdata_size          : hex 100  	dec 256
format                 : hex 2  	dec 2      	CDL formatted
features               : hex 0  	dec 0      	default
""")
        self.assertEqual(dm.get_dasd_info(self.devname), None)

    def test_get_dasd_info_missing_format(self, run_mock):
        run_mock.return_value = CompletedProcess('', 0, stdout="""

--- general DASD information --------------------------------------------------
device node            : /dev/dasde
type                   : ECKD
device type            : hex 3390  	dec 13200

--- DASD geometry -------------------------------------------------------------
number of cylinders    : hex d0b  	dec 3339
tracks per cylinder    : hex f  	dec 15
blocks per track       : hex c  	dec 12
blocksize              : hex 1000  	dec 4096

--- extended DASD information -------------------------------------------------
real device number     : hex 0  	dec 0
status                 : hex 5  	dec 5
confdata_size          : hex 100  	dec 256
features               : hex 0  	dec 0      	default
""")
        self.assertEqual(dm.get_dasd_info(self.devname), None)

    def test_get_dasd_info_dasdview_fails(self, run_mock):
        run_mock.side_effect = CalledProcessError(1, 'dasdview')
        self.assertEqual(dm.get_dasd_info(self.devname), None)

    def test_get_dasd_info_type_cdl(self, run_mock):
        run_mock.return_value = CompletedProcess('', 0, stdout="""

--- general DASD information --------------------------------------------------
device node            : /dev/dasde
type                   : ECKD
device type            : hex 3390  	dec 13200

--- DASD geometry -------------------------------------------------------------
number of cylinders    : hex d0b  	dec 3339
tracks per cylinder    : hex f  	dec 15
blocks per track       : hex c  	dec 12
blocksize              : hex 1000  	dec 4096

--- extended DASD information -------------------------------------------------
real device number     : hex 0  	dec 0
format                 : hex 2  	dec 2      	CDL formatted

""")
        dtype, _, _, _ = dm.get_dasd_info(self.devname)
        self.assertEqual(dtype, 'CDL')

    def test_get_dasd_info_type_ldl(self, run_mock):
        run_mock.return_value = CompletedProcess('', 0, stdout="""

--- general DASD information --------------------------------------------------
device node            : /dev/dasde
type                   : ECKD
device type            : hex 3390  	dec 13200

--- DASD geometry -------------------------------------------------------------
number of cylinders    : hex d0b  	dec 3339
tracks per cylinder    : hex f  	dec 15
blocks per track       : hex c  	dec 12
blocksize              : hex 1000  	dec 4096

--- extended DASD information -------------------------------------------------
real device number     : hex 0  	dec 0
format                 : hex 1  	dec 1      	LDL formatted

""")
        dtype, _, _, _ = dm.get_dasd_info(self.devname)
        self.assertEqual(dtype, 'LDL')

    def test_get_dasd_info_type_fba(self, run_mock):
        run_mock.return_value = CompletedProcess('', 0, stdout="""

--- general DASD information --------------------------------------------------
device node            : /dev/dasde
type                   : FBA
device type            : hex 3390  	dec 13200

--- DASD geometry -------------------------------------------------------------
number of cylinders    : hex d0b  	dec 3339
tracks per cylinder    : hex f  	dec 15
blocks per track       : hex c  	dec 12
blocksize              : hex 1000  	dec 4096

--- extended DASD information -------------------------------------------------
real device number     : hex 0  	dec 0
format                 : hex 3  	dec 3      	FBA formatted

""")
        dtype, _, _, _ = dm.get_dasd_info(self.devname)
        self.assertEqual(dtype, 'FBA')


if __name__ == '__main__':
    unittest.main()
