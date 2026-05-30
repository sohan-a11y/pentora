import httpx
import pytest
import respx

from pentora.auth.otp_brute import OtpResult, brute_otp, generate_otps


def test_generate_otps_pads_to_length() -> None:
    four = list(generate_otps(4, limit=3))
    assert four == ["0000", "0001", "0002"]
    six = list(generate_otps(6, limit=1))
    assert six == ["000000"]


@pytest.mark.asyncio
@respx.mock
async def test_brute_otp_finds_correct_code() -> None:
    def responder(request: httpx.Request) -> httpx.Response:
        body = request.content.decode()
        if '"0003"' in body:
            return httpx.Response(200, json={"status": "ok"})
        return httpx.Response(401, json={"error": "invalid"})

    respx.post("https://t.example/verify").mock(side_effect=responder)

    async def is_success(resp: httpx.Response) -> bool:
        return resp.status_code == 200

    async with httpx.AsyncClient() as client:
        result = await brute_otp(
            client,
            "https://t.example/verify",
            length=4,
            field="otp",
            success=is_success,
            limit=10,
            throttle_s=0.0,
        )
    assert isinstance(result, OtpResult)
    assert result.found is True
    assert result.code == "0003"
    assert result.attempts == 4


@pytest.mark.asyncio
@respx.mock
async def test_brute_otp_exhausts_without_match() -> None:
    respx.post("https://t.example/verify").mock(return_value=httpx.Response(401))

    async def is_success(resp: httpx.Response) -> bool:
        return resp.status_code == 200

    async with httpx.AsyncClient() as client:
        result = await brute_otp(
            client,
            "https://t.example/verify",
            length=4,
            field="otp",
            success=is_success,
            limit=5,
            throttle_s=0.0,
        )
    assert result.found is False
    assert result.code is None
    assert result.attempts == 5


@pytest.mark.asyncio
@respx.mock
async def test_brute_otp_applies_throttle_between_requests() -> None:
    respx.post("https://t.example/verify").mock(return_value=httpx.Response(401))
    sleeps: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        sleeps.append(seconds)

    async def is_success(resp: httpx.Response) -> bool:
        return False

    async with httpx.AsyncClient() as client:
        await brute_otp(
            client,
            "https://t.example/verify",
            length=4,
            field="otp",
            success=is_success,
            limit=3,
            throttle_s=0.5,
            sleep=fake_sleep,
        )
    assert sleeps == [0.5, 0.5, 0.5]
