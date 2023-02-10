import os
import vt

VT_APIKEY = os.getenv("VT_APIKEY")


def vt_url_malicious(url):
    client = vt.Client(VT_APIKEY)
    url_id = vt.url_id(url)
    url = client.get_object("/urls/{}", url_id)
    if url.last_analysis_stats["malicious"] > 0:
        return True
    else:
        return False
