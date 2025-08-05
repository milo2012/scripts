import requests
import tempfile
import argparse
import concurrent.futures
import sys
import re

import Cocoa
import Vision
import Quartz

from urllib.parse import urljoin, urlparse
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


def download_image_from_url(url):
    try:
        response = requests.get(url, timeout=10, verify=False)
        response.raise_for_status()
        temp = tempfile.NamedTemporaryFile(delete=False, suffix=".png")
        temp.write(response.content)
        temp.close()
        return temp.name
    except Exception as e:
        return None


def nsimage_from_path(path):
    return Cocoa.NSImage.alloc().initWithContentsOfFile_(path)


def bitmap_rep_from_nsimage(nsimage):
    tiff = nsimage.TIFFRepresentation()
    return Cocoa.NSBitmapImageRep.imageRepWithData_(tiff)


def perform_ocr(image_path):
    nsimage = nsimage_from_path(image_path)
    if nsimage is None:
        return None

    bitmap = bitmap_rep_from_nsimage(nsimage)
    if bitmap is None:
        return None

    ciimage = Quartz.CIImage.imageWithData_(bitmap.TIFFRepresentation())
    handler = Vision.VNImageRequestHandler.alloc().initWithCIImage_options_(ciimage, None)

    recognized_text = []

    def completion_handler(request, error):
        if error:
            return
        for observation in request.results():
            top_candidate = observation.topCandidates_(1)
            if top_candidate:
                recognized_text.append(top_candidate[0].string())

    request = Vision.VNRecognizeTextRequest.alloc().initWithCompletionHandler_(completion_handler)
    request.setRecognitionLevel_(Vision.VNRequestTextRecognitionLevelAccurate)

    handler.performRequests_error_([request], None)
    return "\n".join(recognized_text)


def scan_url(base_url):
    base_url = base_url.rstrip("/")
    user_url = urljoin(base_url + "/", "user")
    parsed = urlparse(base_url)
    host = parsed.netloc

    try:
        resp = requests.get(user_url, verify=False, timeout=10)
        if resp.status_code == 200 and "<title>PaperCut Login" in resp.text:
            image_url = urljoin(base_url + "/", "images/login-logo2@2x.png?66453papercut-mf")
            path = download_image_from_url(image_url)
            if path:
                text = perform_ocr(path)
                if text:
                    lines = text.strip().split("\n")
                    version_line = lines[-1].strip()
                    # Remove non-version noise if needed
                    version_line = re.sub(r"[^\w.\- ]+", "", version_line)
                    return f"{host} - PaperCut {version_line}"
            return f"{host} - PaperCut (OCR failed)"
        else:
            return None
    except Exception:
        return None


def main():
    parser = argparse.ArgumentParser(description="Detect PaperCut version via OCR.")
    parser.add_argument("-u", "--url", help="Single target base URL (e.g., https://x.x.x.x:9191)")
    parser.add_argument("-f", "--file", help="File with list of URLs (one per line)")
    args = parser.parse_args()

    results = []

    if args.url:
        result = scan_url(args.url)
        if result:
            print(result)

    elif args.file:
        with open(args.file, "r") as f:
            urls = [line.strip() for line in f if line.strip()]
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            future_to_url = {executor.submit(scan_url, url): url for url in urls}
            for future in concurrent.futures.as_completed(future_to_url):
                res = future.result()
                if res:
                    print(res)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
