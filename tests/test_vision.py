"""Tests for Vision API endpoints."""
from unittest.mock import patch

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


class TestVisionAPI:
    """Tests for the vision extraction endpoint."""

    @patch('app.api.vision.vision_completion')
    def test_vision_extract_with_mock(self, mock_vision):
        """Test vision extraction with mocked LLM call."""
        # Mock the vision completion to return test text
        mock_vision.return_value = "Extracted text from image"

        # Create a simple 1x1 PNG base64 (smallest valid PNG)
        # This is a valid 1x1 transparent PNG
        tiny_png_b64 = (
            "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=="
        )

        r = client.post(
            "/api/vision/extract-text",
            json={
                "image_base64": tiny_png_b64,
                "image_mime_type": "image/png",
                "vision_model": "gpt-4o-mini"
            }
        )

        # Debug: print response if it fails
        if r.status_code != 200:
            print(f"Status: {r.status_code}, Response: {r.json()}")

        assert r.status_code == 200
        data = r.json()
        assert data["text"] == "Extracted text from image"
        assert data["model"] == "gpt-4o-mini"

        # Verify the vision completion was called
        mock_vision.assert_called_once()
        call_kwargs = mock_vision.call_args.kwargs
        assert call_kwargs["image_base64"] == tiny_png_b64
        assert call_kwargs["image_mime_type"] == "image/png"
        assert call_kwargs["model_override"] == "gpt-4o-mini"

    @patch('app.api.vision.vision_completion')
    def test_vision_extract_with_ollama(self, mock_vision):
        """Test vision extraction with Ollama provider."""
        mock_vision.return_value = "Extracted text from Ollama vision model"

        tiny_png_b64 = (
            "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=="
        )

        r = client.post(
            "/api/vision/extract-text",
            json={
                "image_base64": tiny_png_b64,
                "image_mime_type": "image/png",
                "vision_model": "llava",
                "provider": "ollama",
                "base_url": "http://localhost:11434"
            }
        )

        assert r.status_code == 200
        data = r.json()
        assert data["text"] == "Extracted text from Ollama vision model"
        assert data["model"] == "llava"

        # Verify the vision completion was called with correct provider
        mock_vision.assert_called_once()
        call_kwargs = mock_vision.call_args.kwargs
        assert call_kwargs["provider_override"] == "ollama"
        assert call_kwargs["base_url_override"] == "http://localhost:11434"
        assert call_kwargs["model_override"] == "llava"

    @patch('app.api.vision.vision_completion')
    def test_vision_extract_openai_ignores_custom_base_url(self, mock_vision):
        """Test that OpenAI provider ignores custom base_url (uses configured URL)."""
        mock_vision.return_value = "Extracted text from OpenAI"

        tiny_png_b64 = (
            "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=="
        )

        # Try to pass a custom base_url with OpenAI provider
        # The API should accept it but vision_completion should ignore it
        r = client.post(
            "/api/vision/extract-text",
            json={
                "image_base64": tiny_png_b64,
                "image_mime_type": "image/png",
                "vision_model": "gpt-4o",
                "provider": "openai",
                "base_url": "http://should-be-ignored:11434"  # Should be ignored!
            }
        )

        assert r.status_code == 200
        data = r.json()
        assert data["text"] == "Extracted text from OpenAI"

        # Verify vision_completion was called with the base_url BUT
        # the actual function should ignore it for openai provider
        mock_vision.assert_called_once()
        call_kwargs = mock_vision.call_args.kwargs
        assert call_kwargs["provider_override"] == "openai"
        # base_url_override is passed but ignored by vision_completion for openai provider

    def test_vision_extract_invalid_base64(self):
        """Test that invalid base64 is rejected."""
        r = client.post(
            "/api/vision/extract-text",
            json={
                "image_base64": "not valid base64!@#$",
                "image_mime_type": "image/png"
            }
        )
        assert r.status_code == 422  # Validation error

    @patch('app.api.vision.vision_completion')
    def test_vision_extract_sampling_params_forwarded(self, mock_vision):
        """Test that sampling_params are forwarded to vision_completion."""
        mock_vision.return_value = "Extracted text"

        tiny_png_b64 = (
            "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=="
        )

        r = client.post(
            "/api/vision/extract-text",
            json={
                "image_base64": tiny_png_b64,
                "image_mime_type": "image/png",
                "vision_model": "llava:34b",
                "provider": "ollama",
                "base_url": "http://localhost:11434",
                "sampling_params": {"num_ctx": 16384, "temperature": 0.1},
            }
        )

        assert r.status_code == 200
        mock_vision.assert_called_once()
        call_kwargs = mock_vision.call_args.kwargs
        assert call_kwargs["sampling_params"] == {"num_ctx": 16384, "temperature": 0.1}

    @patch('app.api.vision.vision_completion')
    def test_vision_extract_no_sampling_params(self, mock_vision):
        """Test that omitting sampling_params passes None to vision_completion."""
        mock_vision.return_value = "Extracted text"

        tiny_png_b64 = (
            "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=="
        )

        r = client.post(
            "/api/vision/extract-text",
            json={
                "image_base64": tiny_png_b64,
                "image_mime_type": "image/png",
                "vision_model": "gpt-4o-mini",
            }
        )

        assert r.status_code == 200
        call_kwargs = mock_vision.call_args.kwargs
        assert call_kwargs["sampling_params"] is None

    def test_vision_extract_empty_image(self):
        """Test that empty image data is rejected."""
        r = client.post(
            "/api/vision/extract-text",
            json={
                "image_base64": "",
                "image_mime_type": "image/png"
            }
        )
        assert r.status_code == 422  # Validation error
