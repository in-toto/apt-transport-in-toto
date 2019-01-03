#!/usr/bin/env python
"""
<Program Name>
  test_units.py

<Author>
  Lukas Puehringer <lukas.puehringer@nyu.edu>

<Started>
  Jan 02, 2019.

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Test individual selected units of the intoto transport that are not covered
  by the more holistic tests in `test_intoto.py`, which mock and test
  full use case scenarios.

<Usage>
  python -m unittest tests.test_units

"""
import mock
import unittest
import intoto
from intoto import (serialize_one, deserialize_one, _intoto_parse_config,
    _intoto_verify, LOG_HANDLER_STDERR)



class TestSerialization(unittest.TestCase):
  """Test parts serialization and deserialization functions. """


  def test_serialize_deserialize(self):
    """Test that data is (de)serialized as expected. """
    msg = "601 Configuration\nConfig-Item: 1\nConfig-Item: 2\n\n"
    msg_data = {
      "code": 601,
      "info": "Configuration",
      "fields": [
        ("Config-Item", "1"),
        ("Config-Item", "2"),
      ]
    }
    self.assertEqual(deserialize_one(msg), msg_data)
    self.assertEqual(serialize_one(msg_data), msg)


  def test_deserialize_error(self):
    """Test deserialization errors on malformed data. """
    for msg, error in [
        ("", "Invalid empty message:"),
        ("10000", "Invalid message header:"),
        ("LOL LOL", "Invalid message header status code:"),
        ("1000 LOL", "Invalid message header status code:"),
        ("100 LOL", "Invalid message header info"),
        ("601 Configuration\nConfig-Item", "Invalid header field:")]:
      with self.assertRaises(Exception) as ctx:
        deserialize_one(msg)
      self.assertIn(error, str(ctx.exception))



class TestConfigParser(unittest.TestCase):
  """Test function that parses the `601 Configuration` message. """


  def test_log_level_config(self):
    """Test parsing LogLevel config. """
    def _intoto_parse_config_with_log_level(level):
      """Wrapper for _intoto_parse_config to pass message with specific log
      level. """
      _intoto_parse_config({
        "code": 601,
        "info": "Configuration",
        "fields": [
          ("Config-Item", "APT::Intoto::LogLevel::={}".format(level)),
        ],
      })
    # Backup log level
    level_backup = LOG_HANDLER_STDERR.level

    # Test with bad log level values
    for level in ["1.0", "abc"]:
      _intoto_parse_config_with_log_level(level)
      self.assertNotEqual(LOG_HANDLER_STDERR.level, level)

    # Test with good log level values
    _intoto_parse_config_with_log_level(100)
    self.assertEqual(LOG_HANDLER_STDERR.level, 100)

    # Restore log level
    LOG_HANDLER_STDERR.level = level_backup


  def test_ignore_config_items(self):
    """Test that irrelevant configs are ignored. """
    empty_global_info = {
      "config": {
        "Rebuilders": [],
        "GPGHomedir": "",
        "Layout": "",
        "Keyids": [],
        "NoFail": False
      }
    }

    # Backup and reset global info
    backup_global_info = intoto.global_info
    intoto.global_info = empty_global_info

    # Call config parsing function with irrelevant configs
    _intoto_parse_config({
      "code": 601,
      "info": "Configuration",
      "fields": [
        ("No-Config-Item", "123"),
        ("Config-Item", "APT::Other::Info"),
      ],
    })

    # Global info should still be empty
    self.assertDictEqual(intoto.global_info, empty_global_info)

    # Restore global info
    intoto.global_info = backup_global_info



class TestVerification(unittest.TestCase):
  """Test function that triggers intoto verification (upon reception of
  `201 URI Done` message).

  """


  def test_skip_wrong_name(self):
    """Skip in-toto verification for files with wrong filename. """
    def _intoto_verify_with_filename(fn):
      """Wrapper for _intoto_verify to pass message with specific filename. """
      _intoto_verify({
        "code": 201,
        "info": "URI Done",
        "fields": [
          ("Filename", "{}".format(fn)),
        ],
      })

    for fn in ["not-a-deb.txt", "way_too_may_party.deb", "missing_parts.deb"]:
      with mock.patch("intoto.logger") as mock_logger:
        _intoto_verify_with_filename(fn)
        mock_logger.info.assert_called_with(
            "Skipping in-toto verification for '{}'".format(fn))



if __name__ == "__main__":
  unittest.main()