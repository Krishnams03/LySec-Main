import unittest
from unittest.mock import mock_open, patch

from lysec.monitors.filesystem_monitor import FilesystemMonitor


class _DummyAlert:
    def fire(self, **kwargs):
        return None


class FilesystemMonitorTests(unittest.TestCase):
    def _monitor(self) -> FilesystemMonitor:
        cfg = {
            "monitors": {
                "filesystem": {
                    "enabled": True,
                    "mount_watch_roots": ["/media", "/run/media", "/mnt"],
                }
            }
        }
        return FilesystemMonitor(cfg, _DummyAlert())

    def test_discover_mount_points_includes_block_device_mount_outside_roots(self):
        mon = self._monitor()
        mounts = (
            "/dev/sdb1 /run/user/1000/doc exfat rw,relatime 0 0\n"
            "tmpfs /run tmpfs rw,nosuid,nodev 0 0\n"
        )
        with patch("builtins.open", mock_open(read_data=mounts)):
            out = mon._discover_mount_points()
        self.assertIn("/run/user/1000/doc", out)

    def test_discover_mount_points_includes_gvfs_fuse_mount(self):
        mon = self._monitor()
        mounts = (
            "gvfsd-fuse /run/user/1000/gvfs fuse.gvfsd-fuse rw,nosuid,nodev 0 0\n"
        )
        with patch("builtins.open", mock_open(read_data=mounts)):
            out = mon._discover_mount_points()
        self.assertIn("/run/user/1000/gvfs", out)

    def test_discover_gvfs_roots_collects_all_users(self):
        with patch("os.path.isdir") as isdir, patch("os.listdir", return_value=["1000", "1001"]):
            def _isdir(path: str) -> bool:
                return path in {
                    "/run/user",
                    "/run/user/1000/gvfs",
                    "/run/user/1001/gvfs",
                }

            isdir.side_effect = _isdir
            out = FilesystemMonitor._discover_gvfs_roots()

        self.assertEqual(out, ["/run/user/1000/gvfs", "/run/user/1001/gvfs"])

    def test_discover_gvfs_roots_returns_empty_when_base_missing(self):
        with patch("os.path.isdir", return_value=False):
            out = FilesystemMonitor._discover_gvfs_roots()
        self.assertEqual(out, [])


if __name__ == "__main__":
    unittest.main()
