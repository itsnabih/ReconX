"""Unit tests for CancellationToken."""

import unittest

from reconx.core.cancellation import CancellationToken


class TestCancellationToken(unittest.TestCase):
    def test_initial_state(self) -> None:
        token = CancellationToken()
        self.assertFalse(token.is_cancelled)

    def test_cancel_sets_flag(self) -> None:
        token = CancellationToken()
        token.cancel()
        self.assertTrue(token.is_cancelled)

    def test_cancel_is_idempotent(self) -> None:
        token = CancellationToken()
        called_count = 0

        def on_cancel() -> None:
            nonlocal called_count
            called_count += 1

        token.register_callback(on_cancel)
        token.cancel()
        token.cancel()
        self.assertEqual(called_count, 1)

    def test_callback_registered_after_cancel_runs_immediately(self) -> None:
        token = CancellationToken()
        token.cancel()
        called = False

        def on_cancel() -> None:
            nonlocal called
            called = True

        token.register_callback(on_cancel)
        self.assertTrue(called)

    def test_unregister_callback(self) -> None:
        token = CancellationToken()
        called = False

        def on_cancel() -> None:
            nonlocal called
            called = True

        token.register_callback(on_cancel)
        token.unregister_callback(on_cancel)
        token.cancel()
        self.assertFalse(called)

    def test_child_token_inherits_parent_cancellation(self) -> None:
        parent = CancellationToken()
        child = parent.create_child()

        self.assertFalse(child.is_cancelled)
        parent.cancel()
        self.assertTrue(child.is_cancelled)

    def test_child_token_cancel_does_not_cancel_parent(self) -> None:
        parent = CancellationToken()
        child = parent.create_child()

        child.cancel()
        self.assertTrue(child.is_cancelled)
        self.assertFalse(parent.is_cancelled)
