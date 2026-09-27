from unittest.mock import MagicMock, patch

from vt.llm.provider import OllamaProvider


def test_ollama_provider_constructs_client_with_configured_timeout():
    with patch("ollama.Client") as mock_client_cls:
        mock_client = MagicMock()
        mock_client.chat.return_value = {"message": {"content": '{"ok": true}'}}
        mock_client_cls.return_value = mock_client

        provider = OllamaProvider()
        result = provider.complete_json("system", "user")

        assert result == '{"ok": true}'
        mock_client_cls.assert_called_once()
        _, kwargs = mock_client_cls.call_args
        assert "timeout" in kwargs
        assert kwargs["timeout"] > 0
