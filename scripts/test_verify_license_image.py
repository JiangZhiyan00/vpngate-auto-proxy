"""镜像材料必须与当前源码完全一致，并报告差异文件。"""
import importlib.util
from pathlib import Path
import unittest


spec = importlib.util.spec_from_file_location(
    'verify_license_image', Path(__file__).with_name('verify-license-image.py'))
verify_license_image = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verify_license_image)


class ImageNoticeTests(unittest.TestCase):
    def test_exact_materials_are_accepted(self):
        verify_license_image.verify_file_digests({'当前声明': '摘要'}, {'当前声明': '摘要'}, '运行时材料')

    def test_inherited_old_notice_is_rejected_with_path(self):
        with self.assertRaisesRegex(RuntimeError, '多出 1，示例：旧版本/声明'):
            verify_license_image.verify_file_digests(
                {'当前声明': '摘要'}, {'当前声明': '摘要', '旧版本/声明': '旧摘要'}, '运行时材料')

    def test_missing_and_changed_materials_are_reported(self):
        with self.assertRaises(RuntimeError) as failure:
            verify_license_image.verify_file_digests(
                {'缺失声明': '摘要', '变更声明': '原摘要'}, {'变更声明': '新摘要'}, '运行时材料')
        self.assertIn('缺少 1，示例：缺失声明', str(failure.exception))
        self.assertIn('内容改变 1，示例：变更声明', str(failure.exception))

    def test_empty_materials_cannot_pass(self):
        with self.assertRaisesRegex(RuntimeError, '源码材料清单为空'):
            verify_license_image.verify_file_digests({}, {}, '运行时材料')
