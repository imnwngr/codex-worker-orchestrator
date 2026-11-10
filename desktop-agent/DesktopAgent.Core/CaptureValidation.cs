namespace DesktopAgent.Core;

public static class CaptureValidation
{
    public static bool HasClientContent(byte[] pixels, int width, int height, int left, int top, int right, int bottom)
    {
        if (width < 2 || height < 2 || width > 4096 || height > 4096 || pixels.Length != width * height * 4 ||
            left < 0 || top < 0 || right > width || bottom > height || right - left < 4 || bottom - top < 4)
            return false;
        int first = (top * width + left) * 4, changed = 0;
        for (int y = top; y < bottom; y++)
            for (int x = left; x < right; x++) {
                int offset = (y * width + x) * 4;
                if (pixels[offset] != pixels[first] || pixels[offset + 1] != pixels[first + 1] ||
                    pixels[offset + 2] != pixels[first + 2]) {
                    if (++changed >= 16) return true;
                }
            }
        return false;
    }
}
