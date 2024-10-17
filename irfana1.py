# Decompile by Mardis (Tools By Nain_rabnain)
# Time Succes decompile : 2022-05-22 23:34:12.924217
W = '\033[97;1m'
R = '\033[91;1m'
G = '\033[92;1m'
Y = '\033[93;1m'
B = '\033[94;1m'
P = '\033[95;1m'
C = '\033[96;1m'
N = '\x1b[0m'
global nain
global ok
global cp
import requests
import re
import threading
import os
import sys
import random
import uuid
import base64
from datetime import datetime
from platform import uname,system
from hashlib import md5
from time import sleep, gmtime, strftime
rd='\033[38;5;208m'
grnh='\033[1;32m'
grn='\033[38;5;42m'
rdh='\033[1;31m'
yl='\033[38;5;220m'
bl='\033[38;5;38m'
bk1='\033[38;5;235m'
bk2='\033[38;5;238m'
bk3='\033[38;5;250m'
bk4='\033[38;5;255m';en='\033[0m'
unk=f'\033[38;5;{random.randint(1,200)}m'
line="-"*63
token  = str(md5(str(uname()).encode()).hexdigest())
def approval():
    try:
        token  = str(md5(str(uname()).encode()).hexdigest())
        response = requests.get("https://github.com/Nainalome/Poll/blob/main/Poll.txt")
        if token in response.text:return {"status":"ok"}
        else:return {"status":"no"}
    except:return {"status":"bad"}

def tele():
    return

def banner():
    os.system('cls')
    print(f"""{grnh}
 {line}
\033[1;33m███╗   ██╗ █████╗ ██╗███╗   ██╗
\033[1;32m████╗  ██║██╔══██╗██║████╗  ██║
\033[1;33m██╔██╗ ██║███████║██║██╔██╗ ██║
\033[1;32m██║╚██╗██║██╔══██║██║██║╚██╗██║
\033[1;33m██║ ╚████║██║  ██║██║██║ ╚████║
\033[1;32m╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝
                          
\033[1;32mNAM TO SUNA HOGA PRADEEP MAURYA
\033[;33mCLEAR FECBOOK DATA TO OEPN CP ID JUST NOW
\033[;32mMAZA NA AYE PASSY WAPIS 😁🖕
        
 
••••••••••••••••••••••••••••••••••••••••••••••••••\033[1;33m
  \033[1;32mADMIN   : PRADEEP MAURYA
  \033[1;33mYouTube : HSNAIN TEACH HZ
  \033[1;32mFecbook : PRADEEP MAURYA
   \033[1;33mTEAM.  : PRADEEP X3 NAIN
••••••••••••••••••••••••••••••••••••••••••••••••••\033[1;32m""")
banner()

class FB:

    def __init__(self, user, password, twofa, cookie, jsondata, cv, count):
        self.user = user
        self.password = password
        self.twofa = twofa
        self.cookie = cookie
        self.count = count
        self.cv = cv
        if '1' in cv:
            self.idbv = jsondata['like']['idbv']
            self.camxuc = jsondata['like']['camxuc']
            self.delay = jsondata['like']['delay']
            self.solanlike = jsondata['like']['solanlike']
            text = f'feedback:{self.idbv}'
            self.idbv = base64.b64encode(text.encode()).decode('utf-8')
        if '2' in cv:
            self.idbv = jsondata['cmt']['idbv']
            self.solancmt = jsondata['cmt']['solancmt']
            self.delay = jsondata['cmt']['delay']
            self.countcmt = jsondata['cmt']['countcmt']
            text = f'feedback:{self.idbv}'
            self.idbv = base64.b64encode(text.encode()).decode('utf-8')
        if '3' in cv:
            self.sojoin = jsondata['join']['solanjoin']
            self.delay = jsondata['join']['delay']
        if '4' in cv:
            self.datapoll = jsondata['poll']['datapoll']
            self.soluong = jsondata['poll']['count']

    def login(self):
        try:

            def get_cookie(session):
                data = session.cookies.get_dict()
                ck = ''
                for i in data:
                    kk = data[str(i)]
                    ck += i + '=' + kk + ';'
                return ck
            session = requests.session()
            headers = {'authority': 'mbasic.facebook.com', 'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9', 'content-type': 'application/x-www-form-urlencoded', 'origin': 'https://mbasic.facebook.com', 'sec-ch-ua': '"Chromium";v="104", " Not A;Brand";v="99", "Google Chrome";v="104"', 'sec-ch-ua-mobile': '?0', 'sec-ch-ua-platform': '"Windows"', 'sec-fetch-dest': 'document', 'sec-fetch-mode': 'navigate', 'sec-fetch-site': 'same-origin', 'sec-fetch-user': '?1', 'upgrade-insecure-requests': '1', 'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36'}
            login = session.get('https://mbasic.facebook.com/login/device-based/regular/login/?refsrc=deprecated&lwv=100&refid=8', headers=headers)
            html = login.text
            lsd = html.split('name="lsd" value="')[1].split('"')[0]
            jazoest = html.split('name="jazoest" value="')[1].split('"')[0]
            m_ts = html.split('name="m_ts" value="')[1].split('"')[0]
            li = html.split('name="li" value="')[1].split('"')[0]
            cookie = get_cookie(session)
            headers.update({'cookie': cookie})
            data = {'lsd': lsd, 'jazoest': jazoest, 'm_ts': m_ts, 'li': li, 'try_number': '0', 'unrecognized_tries': '0', 'email': self.user, 'pass': self.password, 'login': 'Log In', 'bi_xrwh': '0'}
            html = session.post('https://mbasic.facebook.com/login/device-based/regular/login/?refsrc=deprecated&lwv=100&refid=8', data=data, headers=headers)
            if 'name="login"' in html.text:
                return False
            cookie = get_cookie(session)
            headers.update({'cookie': cookie})
            html = html.text
            if 'id="approvals_code"' in html:
                if self.twofa == 'no':
                    return False
                fb_dtsg = html.split('name="fb_dtsg" value="')[1].split('"')[0]
                nh = html.split('name="nh" value="')[1].split('"')[0]
                jazoest = html.split('name="jazoest" value="')[1].split('"')[0]
                code = session.get('http://2fa.live/tok/' + self.twofa).json()['token']
                data = {'fb_dtsg': fb_dtsg, 'jazoest': jazoest, 'checkpoint_data': '', 'approvals_code': code, 'codes_submitted': '0', 'submit[Submit Code]': 'Submit Code', 'nh': nh}
                fa = session.post('https://mbasic.facebook.com/login/checkpoint/', data=data, headers=headers)
                cookie = get_cookie(session)
                headers.update({'cookie': cookie})
                if 'id="approvals_code"' in fa.text:
                    return False
                data = {'fb_dtsg': fb_dtsg, 'jazoest': jazoest, 'checkpoint_data': '', 'name_action_selected': 'save_device', 'submit[Continue]': 'Continue', 'nh': nh}
                fa = session.post('https://mbasic.facebook.com/login/checkpoint/', data=data, headers=headers)
                cookie = get_cookie(session)
                headers.update({'cookie': cookie})
                if 'submit[Continue]"' in fa.text:
                    data.pop('name_action_selected')
                    fa = session.post('https://mbasic.facebook.com/login/checkpoint/', data=data, headers=headers)
                    cookie = get_cookie(session)
                    headers.update({'cookie': cookie})
                    data.pop('submit[Continue]')
                    data.update({'submit[This was me]': 'This was me'})
                    fa = session.post('https://mbasic.facebook.com/login/checkpoint/', data=data, headers=headers)
                    cookie = get_cookie(session)
                    headers.update({'cookie': cookie})
                    data.pop('submit[This was me]')
                    data.update({'name_action_selected': 'save_device', 'submit[Continue]': 'Continue'})
                    fa = session.post('https://mbasic.facebook.com/login/checkpoint/', data=data, headers=headers, allow_redirects=False)
                    cookie = get_cookie(session)
                else:
                    fa = session.post('https://mbasic.facebook.com/login/checkpoint/', data=data, headers=headers, allow_redirects=False)
                    cookie = get_cookie(session)
            return cookie
        except:
            return False

    def getuid(self):
        try:
            self.uid = re.findall('c_user=(\\d*)', self.cookie)[0]
        except:
            return False

    def getdata(self):
        html = requests.get(f'https://mbasic.facebook.com/profile.php?id={self.uid}', headers={'cookie': self.cookie}).text
        if 'name="fb_dtsg"' in html:
            try:
                self.fb_dtsg = html.split('name="fb_dtsg" value="')[1].split('"')[0]
            except:
                html = requests.get(f'https://mbasic.facebook.com/profile.php?id={self.uid}', headers={'cookie': self.cookie}).text
                if 'name="fb_dtsg"' in html:
                    self.fb_dtsg = html.split('name="fb_dtsg" value="')[1].split('"')[0]
                else:
                    return False
        else:
            return False
        try:
            app_id = '436761779744620'
            url = f'https://www.facebook.com/dialog/oauth/business/cancel/?app_id={app_id}&version=v12.0&logger_id=&user_scopes[0]=user_birthday&user_scopes[1]=user_religion_politics&user_scopes[2]=user_relationships&user_scopes[3]=user_relationship_details&user_scopes[4]=user_hometown&user_scopes[5]=user_location&user_scopes[6]=user_likes&user_scopes[7]=user_education_history&user_scopes[8]=user_work_history&user_scopes[9]=user_website&user_scopes[10]=user_events&user_scopes[11]=user_photos&user_scopes[12]=user_videos&user_scopes[13]=user_friends&user_scopes[14]=user_about_me&user_scopes[15]=user_posts&user_scopes[16]=email&user_scopes[17]=manage_fundraisers&user_scopes[18]=read_custom_friendlists&user_scopes[19]=read_insights&user_scopes[20]=rsvp_event&user_scopes[21]=xmpp_login&user_scopes[22]=offline_access&user_scopes[23]=publish_video&user_scopes[24]=openid&user_scopes[25]=catalog_management&user_scopes[26]=user_messenger_contact&user_scopes[27]=gaming_user_locale&user_scopes[28]=private_computation_access&user_scopes[29]=instagram_business_basic&user_scopes[30]=user_managed_groups&user_scopes[31]=groups_show_list&user_scopes[32]=pages_manage_cta&user_scopes[33]=pages_manage_instant_articles&user_scopes[34]=pages_show_list&user_scopes[35]=pages_messaging&user_scopes[36]=pages_messaging_phone_number&user_scopes[37]=pages_messaging_subscriptions&user_scopes[38]=read_page_mailboxes&user_scopes[39]=ads_management&user_scopes[40]=ads_read&user_scopes[41]=business_management&user_scopes[42]=instagram_basic&user_scopes[43]=instagram_manage_comments&user_scopes[44]=instagram_manage_insights&user_scopes[45]=instagram_content_publish&user_scopes[46]=publish_to_groups&user_scopes[47]=groups_access_member_info&user_scopes[48]=leads_retrieval&user_scopes[49]=whatsapp_business_management&user_scopes[50]=instagram_manage_messages&user_scopes[51]=attribution_read&user_scopes[52]=page_events&user_scopes[53]=business_creative_transfer&user_scopes[54]=pages_read_engagement&user_scopes[55]=pages_manage_metadata&user_scopes[56]=pages_read_user_content&user_scopes[57]=pages_manage_ads&user_scopes[58]=pages_manage_posts&user_scopes[59]=pages_manage_engagement&user_scopes[60]=whatsapp_business_messaging&user_scopes[61]=instagram_shopping_tag_products&user_scopes[62]=read_audience_network_insights&user_scopes[63]=user_about_me&user_scopes[64]=user_actions.books&user_scopes[65]=user_actions.fitness&user_scopes[66]=user_actions.music&user_scopes[67]=user_actions.news&user_scopes[68]=user_actions.video&user_scopes[69]=user_activities&user_scopes[70]=user_education_history&user_scopes[71]=user_events&user_scopes[72]=user_friends&user_scopes[73]=user_games_activity&user_scopes[74]=user_groups&user_scopes[75]=user_hometown&user_scopes[76]=user_interests&user_scopes[77]=user_likes&user_scopes[78]=user_location&user_scopes[79]=user_managed_groups&user_scopes[80]=user_photos&user_scopes[81]=user_posts&user_scopes[82]=user_relationship_details&user_scopes[83]=user_relationships&user_scopes[84]=user_religion_politics&user_scopes[85]=user_status&user_scopes[86]=user_tagged_places&user_scopes[87]=user_videos&user_scopes[88]=user_website&user_scopes[89]=user_work_history&user_scopes[90]=email&user_scopes[91]=manage_notifications&user_scopes[92]=manage_pages&user_scopes[93]=publish_actions&user_scopes[94]=publish_pages&user_scopes[95]=read_friendlists&user_scopes[96]=read_insights&user_scopes[97]=read_page_mailboxes&user_scopes[98]=read_stream&user_scopes[99]=rsvp_event&user_scopes[100]=read_mailbox&user_scopes[101]=business_creative_management&user_scopes[102]=business_creative_insights&user_scopes[103]=business_creative_insights_share&user_scopes[104]=whitelisted_offline_access&redirect_uri=fbconnect%3A%2F%2Fsuccess&response_types[0]=token&response_types[1]=code&display=page&action=finish&return_scopes=false&return_format[0]=access_token&return_format[1]=code&tp=unspecified&sdk=&selected_business_id=&set_token_expires_in_60_days=false'
            response = requests.post(url, headers={'cookie': self.cookie}, data={'fb_dtsg': str(self.fb_dtsg)})
            self.token = re.findall('access_token=([^"]*)&data_access_expiration_time', response.text)[0]
        except:
            return False

    def get_page(self):
        self.pro5 = []
        try:
            getTokenPage = requests.get('https://graph.facebook.com/v12.0/me/accounts?fields=access_token,additional_profile_id,locations{id}&limit=100&access_token=' + self.token, headers={'cookie': self.cookie})
            if 'error' in getTokenPage.text:
                return
            getTokenPage = getTokenPage.json()['data']
            for get in getTokenPage:
                id_page = get['id']
                token_pro5 = get['access_token']
                id_pro5 = get['additional_profile_id']
                self.pro5.append(id_pro5)
                if 'locations' in str(get):
                    print(f'GET Page Location In Page Main: {id_page}')
                    try:
                        self.get_page_store(token_pro5, id_page)
                    except:
                        pass
        except:
            pass

    def pollpagepro5(self, idpro5, total):
        global cp
        global ok
        if self.cookie[-1] == ';':
            cookie = self.cookie + 'i_user=' + idpro5 + ';'
        else:
            cookie = self.cookie + ';i_user=' + idpro5 + ';'
        headers = {'authority': 'www.facebook.com', 'accept': '*/*', 'accept-language': 'en-US,en;q=0.9', 'content-type': 'application/x-www-form-urlencoded', 'cookie': cookie, 'referer': 'https://www.facebook.com/settings?tab=profile_access', 'sec-ch-prefers-color-scheme': 'light', 'sec-ch-ua': '', 'sec-ch-ua-full-version-list': '', 'sec-ch-ua-mobile': '?0', 'sec-ch-ua-platform': '""', 'sec-ch-ua-platform-version': '""', 'sec-fetch-dest': 'empty', 'sec-fetch-mode': 'cors', 'sec-fetch-site': 'same-origin', 'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.133 Safari/537.36'}
        question_id, option_id, count = self.datapoll.split('|')
        data = {'av': idpro5, 'fb_dtsg': self.fb_dtsg, 'fb_api_caller_class': 'RelayModern', 'fb_api_req_friendly_name': 'useCometPollAddVoteMutation', 'variables': '{"input":{"is_tracking_encrypted":true,"option_id":"' + option_id + '","question_id":"' + question_id + '","actor_id":"' + idpro5 + '","client_mutation_id":"1"},"scale":1,"__relay_internal__pv__IsWorkUserrelayprovider":false}', 'server_timestamps': 'true', 'doc_id': '6681967255191860', 'fb_api_analytics_tags': '["qpl_active_flow_ids=431626709"]'}
        try:
            post = requests.post('https://www.facebook.com/api/graphql/', headers=headers, data=data).json()
        except:
            print('\x1b[1;93m[{}] POLL-ID: \x1b[1;93m{} \x1b[1;93mPAGE-UID: \x1b[1;93m{} Total-Vote: \x1b[1;92m{} '.format(ok, option_id, idpro5, cp))
            cp += 1
            return
        else:
            if 'errors' in str(post):
                print('\x1b[1;93m[{}] POLL-ID: \x1b[1;93m{} \x1b[1;93mPAGE-UID: \x1b[1;93m{} Total-Vote: \x1b[1;92m{} '.format(ok, option_id, idpro5, cp))
                cp += 1
                return
            for get in post['data']['question_add_vote']['question']['options']['nodes']:
                if option_id in str(get):
                    count = get['profile_voters']['count']
                    print('\x1b[1;91m[{}] \x1b[1;92mPOLL-ID: {} PAGE-UID: {} Total-Vote: {} '.format(ok, option_id, idpro5, count))
                    ok += 1

    def joingrpro5(self, idpro5, idgr, total):
        global ok
        global syed
        if self.cookie[-1] == ';':
            cookie = self.cookie + 'i_user=' + idpro5 + ';'
        else:
            cookie = self.cookie + ';i_user=' + idpro5 + ';'
        syed += 1
        headers = {'authority': 'www.facebook.com', 'accept': '*/*', 'accept-language': 'en-US,en;q=0.9', 'content-type': 'application/x-www-form-urlencoded', 'cookie': cookie, 'referer': 'https://www.facebook.com/settings?tab=profile_access', 'sec-ch-prefers-color-scheme': 'light', 'sec-ch-ua': '', 'sec-ch-ua-full-version-list': '', 'sec-ch-ua-mobile': '?0', 'sec-ch-ua-platform': '""', 'sec-ch-ua-platform-version': '""', 'sec-fetch-dest': 'empty', 'sec-fetch-mode': 'cors', 'sec-fetch-site': 'same-origin', 'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.133 Safari/537.36'}
        data = {'fb_dtsg': self.fb_dtsg, 'fb_api_caller_class': 'RelayModern', 'fb_api_req_friendly_name': 'GroupCometJoinForumMutation', 'variables': '{"feedType":"DISCUSSION","groupID":"' + idgr + '","imageMediaType":"image/x-auto","input":{"action_source":"GROUPS_ENGAGE_TAB","attribution_id_v2":"GroupsCometCrossGroupFeedRoot.react,comet.groups.feed,tap_tabbar,1667116100089,433821,2361831622,","group_id":"' + idgr + '","group_share_tracking_params":null,"actor_id":"' + idpro5 + '","client_mutation_id":"2"},"inviteShortLinkKey":null,"isChainingRecommendationUnit":false,"isEntityMenu":false,"scale":1,"source":"GROUPS_ENGAGE_TAB","renderLocation":"group_mall","__relay_internal__pv__GlobalPanelEnabledrelayprovider":false,"__relay_internal__pv__GroupsCometEntityMenuEmbeddedrelayprovider":true}', 'server_timestamps': 'true', 'doc_id': '5915153095183264'}
        response = requests.post('https://www.facebook.com/api/graphql/', headers=headers, data=data).text
        print('\x1b[1;91m[{}] \x1b[1;92mPOLL-ID: {} PAGE-UID: {} | Join Success'.format(syed, idgr, idpro5))
        ok += 1

    def cmt(self, idpro5, total):
        global ok
        if self.cookie[-1] == ';':
            cookie = self.cookie + 'i_user=' + idpro5 + ';'
        else:
            cookie = self.cookie + ';i_user=' + idpro5 + ';'
        headers = {'authority': 'www.facebook.com', 'accept': '*/*', 'accept-language': 'en-US,en;q=0.9', 'content-type': 'application/x-www-form-urlencoded', 'cookie': cookie, 'referer': 'https://www.facebook.com/settings?tab=profile_access', 'sec-ch-prefers-color-scheme': 'light', 'sec-ch-ua': '', 'sec-ch-ua-full-version-list': '', 'sec-ch-ua-mobile': '?0', 'sec-ch-ua-platform': '""', 'sec-ch-ua-platform-version': '""', 'sec-fetch-dest': 'empty', 'sec-fetch-mode': 'cors', 'sec-fetch-site': 'same-origin', 'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.133 Safari/537.36'}
        noidung = random.choice(open('comment.txt', mode='r', encoding='utf-8').read().split('\n'))
        data = {'fb_dtsg': self.fb_dtsg, 'fb_api_caller_class': 'RelayModern', 'fb_api_req_friendly_name': 'CometUFICreateCommentMutation', 'variables': '{"displayCommentsFeedbackContext":null,"displayCommentsContextEnableComment":null,"displayCommentsContextIsAdPreview":null,"displayCommentsContextIsAggregatedShare":null,"displayCommentsContextIsStorySet":null,"feedLocation":"PERMALINK","feedbackSource":2,"focusCommentID":null,"groupID":null,"includeNestedComments":false,"input":{"attachments":null,"feedback_id":"' + self.idbv + '","formatting_style":null,"message":{"ranges":[],"text":"' + noidung + '"},"attribution_id_v2":"CometSinglePostRoot.react,comet.post.single,via_cold_start,1692175639975,676866,,","is_tracking_encrypted":true,"tracking":["AZVuNDRPni4Q9--BKAtfuWNHMy_89-NxE3pTjMT9_lOt3iM-qSkUzLEZ_FeFl_sq_zGZXfu1Fu2tgEDHR74HuGk2k2JwNfQuV71T2tiowryfVZovjCFl_Bo6_xr4CpG2rlkfQoGvpNv3AvFpm1eCLJZghuF4Wy5Kj7hc57RT6pX0l7OIcseByxSD8bm81CPU3-sIw9a3vx_cYDJKn2GxVBrkGeK_FUpFuxdMdQHzVQ7j44_D858NuZ_ulXBRLfPJCg5tHChFqmeHOAXCCV1GDRhtdeuoa-yyDtVGZwY7EY8F51nC8PBCYrATMpXr2W0w6PrWCyQFXSDrZWyUDrMq6QjnjQX2DifScfOmUKXYFWlbaetXELak_wuDysgcTT68SyCpUPqhQ-Vhp9LHPu8f7GjotHG4bXKoV0SI1azRwmspmG5KCqz1eXDLZFDYiUQjZHuncSXsV3xl--AHwvNggXxeoxe9PVYhHkDtf8I-h4_T5xj-PnHPrlf0lqo2kmojPGkNPriIOPDCbaOcyeXn2DRarKaR1sC_5YI31m3cyohfef_ZhBmnU4w9DUhxcHxQN3mqp_an5A3H2x4Z_RQ3ymOIADDRA4hO5AGFrlPFxutuNoimAGUEZjUr0S8TScHcUD4FfooX0WPC5sfAco8nhlfiimEFL7oe0LwgK3e4bLOVVW-gIpjHP9z2A7S9Sd87jaeqXYYr8NoJETpAn1YFxDSbtrkF3_jnlvgMKfe01ODdiBbc3sIDmh72H-152z_qS3Y_ihz4983UXURphxRcEGX3M0aHB3Uhi7SvKMnXKUbA9P2ErZJ9ify8qujIsigmhK6j5fXBT1vu5ZS4EDCeUty1ogYFfCuY4dBvcuhx6N7FkXsJQ08etPNz-3WvylFOAyP5b2HAcXpgmV-F-3ShhkTNPhaMW2ny6FlndR1aniY--Tbhib3l7dvOcs_rj-A-OrV6v4vRKBSlwF2l6h8J2sysriPzUJgSMLVlCfzvzSHfqtK6DzHt2lpHUtlSNtJ6rw_-LJYfJ7JNFDPQT00PODuYlKVkkZWJLX_mxkkCKibmzUfl6_hmM6k-w1gTPwR5H7Q","{\\"assistant_caller\\":\\"comet_above_composer\\",\\"conversation_guide_session_id\\":\\"' + str(uuid.uuid4()) + '\\",\\"conversation_guide_shown\\":null}"],"feedback_source":"OBJECT","idempotence_token":"client:' + str(uuid.uuid4()) + '","session_id":"' + str(uuid.uuid4()) + '","actor_id":"' + idpro5 + '","client_mutation_id":"4"},"inviteShortLinkKey":null,"renderLocation":null,"scale":1,"useDefaultActor":false,"UFI2CommentsProvider_commentsKey":"CometSinglePostRoute"}', 'server_timestamps': 'true', 'doc_id': '6379115828844234'}
        reaction = requests.post('https://www.facebook.com/api/graphql/', headers=headers, data=data).text
        print('\x1b[1;91m[{}]\x1b[1;92mID: {}|ID Profile: {}|Comment-Done'.format(str(ok), self.uid, idpro5))
        ok += 1

    def reaction(self, reaction, idpro5, total):
        global ok
        global syed
        if self.cookie[-1] == ';':
            cookie = self.cookie + 'i_user=' + idpro5 + ';'
        else:
            cookie = self.cookie + ';i_user=' + idpro5 + ';'
        syed += 1
        headers = {'authority': 'www.facebook.com', 'accept': '*/*', 'accept-language': 'en-US,en;q=0.9', 'content-type': 'application/x-www-form-urlencoded', 'cookie': cookie, 'referer': 'https://www.facebook.com/settings?tab=profile_access', 'sec-ch-prefers-color-scheme': 'light', 'sec-ch-ua': '', 'sec-ch-ua-full-version-list': '', 'sec-ch-ua-mobile': '?0', 'sec-ch-ua-platform': '""', 'sec-ch-ua-platform-version': '""', 'sec-fetch-dest': 'empty', 'sec-fetch-mode': 'cors', 'sec-fetch-site': 'same-origin', 'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.133 Safari/537.36'}
        data = {'fb_dtsg': self.fb_dtsg, 'fb_api_caller_class': 'RelayModern', 'fb_api_req_friendly_name': 'CometUFIFeedbackReactMutation', 'variables': '{"input":{"attribution_id_v2":"ProfileCometTimelineListViewRoot.react,comet.profile.timeline.list,via_cold_start,1667106623951,429237,190055527696468,","feedback_id":"' + self.idbv + '","feedback_reaction_id":"' + reaction + '","feedback_source":"PROFILE","is_tracking_encrypted":true,"tracking":["AZXg8_yM_zhwrTY7oSTw1K93G-sycXrSreRnRk66aBJ9mWkbSuyIgNqL0zHEY_XgxepV1XWYkuv2C5PuM14WXUB9NGsSO8pPe8qDZbqCw5FLQlsGTnh5w9IyC_JmDiRKOVh4gWEJKaTdTOYlGT7k5vUcSrvUk7lJ-DXs3YZsw994NV2tRrv_zq1SuYfVKqDboaAFSD0a9FKPiFbJLSfhJbi6ti2CaCYLBWc_UgRsK1iRcLTZQhV3QLYfYOLxcKw4s2b1GeSr-JWpxu1acVX_G8d_lGbvkYimd3_kdh1waZzVW333356_JAEiUMU_nmg7gd7RxDv72EkiAxPM6BA-ClqDcJ_krJ_Cg-qdhGiPa_oFTkGMzSh8VnMaeMPmLh6lULnJwvpJL_4E3PBTHk3tIcMXbSPo05m4q_Xn9ijOuB5-KB5_9ftPLc3RS3C24_7Z2bg4DfhaM4fHYC1sg3oFFsRfPVf-0k27EDJM0HZ5tszMHQ"],"session_id":"' + str(uuid.uuid4()) + '","actor_id":"' + idpro5 + '","client_mutation_id":"1"},"useDefaultActor":false,"scale":1}', 'server_timestamps': 'true', 'doc_id': '5703418209680126'}
        reaction = requests.post('https://www.facebook.com/api/graphql/', headers=headers, data=data).text
        print('\x1b[1;91m[{}]\x1b[1;92mID: {}|ID Profile: {}|Reaction-Success'.format(str(ok), self.uid, idpro5))
        ok += 1

    def maincamxuc(self):

        def type_cx(type):
            if type == '1':
                return '1635855486666999'
            if type == '2':
                return '1678524932434102'
            if type == '3':
                return '613557422527858'
            if type == '4':
                return '478547315650144'
            if type == '5':
                return '115940658764963'
            if type == '6':
                return '908563459236466'
            if type == '7':
                return '444813342392137'
        total = 0
        for idpro5 in self.pro5:
            if self.solanlike <= total:
                break
            reaction = type_cx(random.choice(self.camxuc))
            thread = threading.Thread(target=self.reaction, args=(reaction, idpro5, total))
            thread.start()
            thread.join()
            sleep(self.delay)
            total += 1

    def mainjoin(self):
        l_idgr = open('idgr.txt', mode='r').read().split('\n')
        if l_idgr == []:
            print('Not ID Group')
            return
        total = 0
        for idpro5 in self.pro5:
            try:
                if self.sojoin <= total:
                    break
                idgr = random.choice(l_idgr)
                thread = threading.Thread(target=self.joingrpro5, args=(idpro5, idgr, total))
                thread.start()
                thread.join()
                total += 1
            except:
                continue

    def maincmt(self):
        total = 0
        for i in range(self.solancmt):
            if self.countcmt <= total:
                break
            for idpro5 in self.pro5:
                if self.countcmt <= total:
                    break
                thread = threading.Thread(target=self.cmt, args=(idpro5, total))
                thread.start()
                thread.join()
                sleep(self.delay)
                total += 1

    def mainpoll(self):
        total = 0
        for idpro5 in self.pro5:
            if self.soluong <= total:
                break
            thread = threading.Thread(target=self.pollpagepro5, args=(idpro5, total))
            thread.start()
            thread.join()
            total += 1
            sleep(0)

    def main(self):

        if self.cookie == 'no':
            print(f'User: {self.uid} Login')
            data = self.login()
            if data['status'] == 'Success':
                self.cookie = data['cookie']
        uid = self.getuid()
        if uid == False:
            return
        getdata = self.getdata()
        if getdata == False:
            return
        self.get_page()
        if '1' in self.cv:
            self.maincamxuc()
        elif '2' in self.cv:
            self.maincmt()
        elif '3' in self.cv:
            self.mainjoin()
        elif '4' in self.cv:
            self.mainpoll()

def getpoll(cookie, fb_dtsg):
    try:
        headers = {'authority': 'www.facebook.com', 'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7', 'accept-language': 'en,vi;q=0.9,fr;q=0.8,vi-VN;q=0.7,fr-FR;q=0.6,en-US;q=0.5', 'cache-control': 'max-age=0', 'cookie': cookie, 'dpr': '1', 'sec-ch-prefers-color-scheme': 'light', 'sec-ch-ua': '"Google Chrome";v="119", "Chromium";v="119", "Not?A_Brand";v="24"', 'sec-ch-ua-full-version-list': '"Google Chrome";v="119.0.6045.200", "Chromium";v="119.0.6045.200", "Not?A_Brand";v="24.0.0.0"', 'sec-ch-ua-mobile': '?0', 'sec-ch-ua-model': '""', 'sec-ch-ua-platform': '"Windows"', 'sec-ch-ua-platform-version': '"7.0.0"', 'sec-fetch-dest': 'document', 'sec-fetch-mode': 'navigate', 'sec-fetch-site': 'same-origin', 'sec-fetch-user': '?1', 'upgrade-insecure-requests': '1', 'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36', 'viewport-width': '559'}
        link = input('Add Link Poll: ')
        response = requests.get(link, headers=headers).content
        question_id = str(response).split('Question","id":"')[1].split('"')[0]
        data = {'fb_dtsg': fb_dtsg, 'fb_api_caller_class': 'RelayModern', 'fb_api_req_friendly_name': 'CometUFIVoteCountDialogQuery', 'variables': '{"questionID":"' + question_id + '","scale":1}', 'server_timestamps': 'true', 'doc_id': '6080954902008459'}
        l_optionID = []
        response = requests.post('https://www.facebook.com/api/graphql/', headers=headers, data=data).json()
        for i, get in enumerate(response['data']['question']['options']['nodes']):
            name = get['text']
            votecount = get['voters']['count']
            optionID = get['id']
            l_optionID.append(optionID + '|' + str(votecount))
            print(f'[{str(i + 1)}] Text: {name} Vote: {votecount} OptionID: {optionID}')
        INDEX = int(input('Choice: ')) - 1
        print('OptionID: ' + l_optionID[INDEX].split('|')[0])
        return question_id + '|' + l_optionID[INDEX]
    except:
        return False

def getdatapoll():
    cookie = random.choice(open('cookie.txt', mode='r').read().split('\n'))
    uid = cookie.split('c_user=')[0].split(';')[0]
    html = requests.get(f'https://mbasic.facebook.com/profile.php?id={uid}', headers={'cookie': cookie}).text
    if 'name="fb_dtsg"' in html:
        fb_dtsg = html.split('name="fb_dtsg" value="')[1].split('"')[0]
        datapoll = getpoll(cookie, fb_dtsg)
        if datapoll == False:
            return 'iderror'
        return datapoll
    return False

def run(data, jsondata, loaicv, count):
    if len(data.split('|')) == 3:
        cookie = 'no'
        user = data.split('|')[0]
        password = data.split('|')[1]
        try:
            twofa = data.split('|')[2]
            if twofa == '':
                twofa = 'no'
        except:
            twofa = 'no'
    elif len(data.split('|')) == 2:
        cookie = 'no'
        user = data.split('|')[0]
        password = data.split('|')[1]
        twofa = 'no'
    else:
        user = 'no'
        password = 'no'
        twofa = 'no'
        cookie = data
    main = FB(user, password, twofa, cookie, jsondata, loaicv, count)
    main.main()

def main():
    response = approval()
    if response['status']=='ok':pass
    else:input(f"\033[1;31mACCESS DENIED, NEED APPROVAL\033[0m: \033[32m{token}\033[0m");sys.exit()
    try:
        filedata = open('cookie.txt', mode='r').read().split('\n')
    except:
        filedata = open('cookie.txt', mode='a')
        print('Paste Cookie Or UID|Password|2Fa To File cookie.txt')
    print('\x1b[0;92m[1]Reaction\n[2]Comment\n[3]Join Group\n[4]Poll')
    loaicv = input('Type Work: ')
    jsondata = {}
    if '1' in loaicv:
        idbv = input('ID Post: ')
        print('Type of Reaction\n[1]Like\n[2]LOVE\n[3]Care\n[4]Wow\n[5]Haha\n[6]SAD\n[7]ANGRY\nIf You Want To Use Multiple Reaction, Add + To Each Reaction\nFor example:1+2+4')
        camxuc = input('Type Reaction: ').split('+')
        solantha = int(input('Count Reaction: '))
        delay = int(input('Delay: '))
        json = {'like': {'idbv': idbv, 'camxuc': camxuc, 'delay': delay, 'solanlike': solantha}}
        jsondata.update(json)
    if '2' in loaicv:
        if '1' not in loaicv:
            idbv = input('ID Post: ')
            delay = int(input('Delay: '))
        countcmt = int(input('Count CMT: '))
        solancmt = int(input('Count CMT/1 Page: '))
        json = {'cmt': {'idbv': idbv, 'solancmt': solancmt, 'delay': delay, 'countcmt': countcmt}}
        jsondata.update(json)
    if '3' in loaicv:
        solanjoin = int(input('Count Join: '))
        if '2' not in loaicv:
            delay = int(input('Delay: '))
        json = {'join': {'delay': delay, 'solanjoin': solanjoin}}
        jsondata.update(json)
    if '4' in loaicv:
        datapoll = getdatapoll()
        if datapoll == False:
            print('Link Cookie Expire')
            input()
            quit()
        elif datapoll == 'iderror':
            print('Link Poll ERROR')
            input()
            quit()
        countpoll = int(input('Count Poll: '))
        json = {'poll': {'datapoll': datapoll, 'count': countpoll}}
        jsondata.update(json)
    for data in filedata:
        try:
            thread_ = threading.Thread(target=run, args=(data, jsondata, loaicv, count))
            l_thread.append(thread_)
            thread_.start()
        except:
            continue
l_thread = []
count = 0
syed = 0
cp = 0
ok = 0
main()
threading.Thread(target=tele).start()
for thread in l_thread:
    thread.join()
print('\n\x1b[1;92mSoftware-Creator: USU Finisher \x1b[1;92m]\nFile-Successfully-Done\nSuccess-Total-Votes-[\x1b[1;93m{}\x1b[1;92m]-Done\nFailed-Total-Votes-[\x1b[1;93m{}\x1b[1;92m]-Done'.format(str(ok), str(cp)))

input()