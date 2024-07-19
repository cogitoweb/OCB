# -*- coding: utf-8 -*-
# Part of Odoo. See LICENSE file for full copyright and licensing details.

import unittest
from odoo.addons.website.models.website import slugify, unslug


class TestUnslug(unittest.TestCase):

    def test_unslug(self):
        tests = {
            '': (None, None),
            'foo': (None, None),
            'foo-': (None, None),
            '-': (None, None),
            'foo-1': ('foo', 1),
            'foo-bar-1': ('foo-bar', 1),
            'foo--1': ('foo', -1),
            '1': (None, 1),
            '1-1': ('1', 1),
            '--1': (None, None),
            'foo---1': (None, None),
            'foo1': (None, None),
        }

        for slug, expected in tests.items():
            self.assertEqual(unslug(slug), expected)


class TestTitleToSlug(unittest.TestCase):
    """
    Those tests should pass with or without python-slugify
    See website/models/website.py slugify method
    """

    def test_spaces(self):
        self.assertEqual(
            "spaces",
            slugify("   spaces   ")
        )

    def test_unicode(self):
        self.assertEqual(
            "heterogeneite",
            slugify("hétérogénéité")
        )

    def test_underscore(self):
        self.assertEqual(
            "one-two",
            slugify("one_two")
        )

    def test_caps(self):
        self.assertEqual(
            "camelcase",
            slugify("CamelCase")
        )

    def test_special_chars(self):
        self.assertEqual(
            "o-d-o-o",
            slugify("o!#d{|\o/@~o&%^?")
        )

    def test_str_to_unicode(self):
        self.assertEqual(
            "espana",
            slugify("España")
        )

    def test_numbers(self):
        self.assertEqual(
            "article-1",
            slugify("Article 1")
        )

    def test_all(self):
        self.assertEqual(
            "do-you-know-martine-a-la-plage",
            slugify("Do YOU know 'Martine à la plage' ?")
        )
