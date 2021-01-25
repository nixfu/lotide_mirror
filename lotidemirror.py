#!/usr/bin/python3 -u

# =============================================================================
# IMPORTS
# =============================================================================
import re
import configparser
import logging
import logging.handlers
import time
import os
import sys
from enum import Enum
import praw
import prawcore
import operator
import random
import yaml
import re
import requests
import sqlite3
import pprint
import ssl
pp = pprint.PrettyPrinter(indent=4)
import json
sys.path.append("%s/github/bots/userdata" % os.getenv("HOME"))
from requests.exceptions import HTTPError


# =============================================================================
# GLOBALS
# =============================================================================
# Reads the config file
config = configparser.ConfigParser()
config.read("bot.cfg")
config.read("auth.cfg")

Settings = {}
Settings = {s: dict(config.items(s)) for s in config.sections()}



ENVIRONMENT = config.get("BOT", "environment")
DEV_USER_NAME = config.get("BOT", "dev_user")
RUNNING_FILE = "bot.pid"

if Settings['Config']['loglevel'] == "debug":
    LOG_LEVEL = logging.DEBUG
else:
    LOG_LEVEL = logging.INFO
LOG_FILENAME = Settings['Config']['logfile']
LOG_FILE_INTERVAL = 2
LOG_FILE_BACKUPCOUNT = 5
LOG_FILE_MAXSIZE = 5000 * 256

logger = logging.getLogger('bot')
logger.setLevel(LOG_LEVEL)
log_formatter = logging.Formatter('%(levelname)-8s:%(asctime)s:%(lineno)4d - %(message)s')
log_stderrHandler = logging.StreamHandler()
log_stderrHandler.setFormatter(log_formatter)
logger.addHandler(log_stderrHandler)
if LOG_FILENAME:
    log_fileHandler = logging.handlers.TimedRotatingFileHandler(LOG_FILENAME, when='d', interval=LOG_FILE_INTERVAL, backupCount=LOG_FILE_BACKUPCOUNT) 
    log_fileHandler.setFormatter(log_formatter)
    logger.addHandler(log_fileHandler)
logger.propagate = False

os.environ['TZ'] = 'US/Eastern'

# =============================================================================
# FUNCTIONS
# =============================================================================
def create_running_file():
    # creates a file that exists while the process is running
    running_file = open(RUNNING_FILE, "w")
    running_file.write(str(os.getpid()))
    running_file.close()


def create_db():
    # create database tables if don't already exist
    try:
        con = sqlite3.connect(Settings['Config']['dbfile'])
        ccur = con.cursor()
        ccur.execute("CREATE TABLE IF NOT EXISTS processed (id TEXT, epoch INTEGER)")
        con.commit
    except sqlite3.Error as e:
        logger.error("Error2 {}:".format(e.args[0]))
        sys.exit(1)
    finally:
        if con:
            con.close()

def check_processed_sql(messageid):
    logging.debug("Check processed for id=%s" % messageid)
    try:
        con = sqlite3.connect(Settings['Config']['dbfile'])
        qcur = con.cursor()
        qcur.execute('''SELECT id FROM processed WHERE id=?''', (messageid,))
        row = qcur.fetchone()
        if row:
            return True
        else:
            return False
    except sqlite3.Error as e:
        logger.error("Error2 {}:".format(e.args[0]))
        sys.exit(1)
    finally:
        if con:
            con.close()


def save_processed_sql(messageid):
    logging.debug("Save processed for id=%s" % messageid)
    try:
        con = sqlite3.connect(Settings['Config']['dbfile'])
        qcur = con.cursor()
        qcur.execute('''SELECT id FROM processed WHERE id=?''', (messageid,))
        row = qcur.fetchone()
        if row:
            return True
        else:
            icur = con.cursor()
            insert_time = int(round(time.time()))
            icur.execute("INSERT INTO processed VALUES(?, ?)",
                         [messageid, insert_time])
            con.commit()
            return False
    except sqlite3.Error as e:
        logger.error("SQL Error:" % e)
    finally:
        if con:
            con.close()



def build_multireddit_groups(subreddits):
    """Splits a subreddit list into groups if necessary (due to url length)."""
    multireddits = []
    current_multi = []
    current_len = 0
    for sub in subreddits:
        if current_len > 3300:
            multireddits.append(current_multi)
            current_multi = []
            current_len = 0
        current_multi.append(sub)
        current_len += len(sub) + 1
    multireddits.append(current_multi)
    return multireddits

def process_submission(submission,lotideToken):
    authorname = ""
    subname = ""
    searchsubs = []
    subreddit = submission.subreddit
    subname = str(submission.subreddit.display_name).lower()
    authorname = str(submission.author)
    subtime = submission.created_utc
    authorRedditLink = "http://reddit.com/user/%s" % authorname
    #lotideCommunity = Settings['lotide']['lotidecommunityid']
    lotideCommunityID = Settings['SubredditCommunities'][subname]
    rsubRedditLink = "http://reddit.com%s" % submission.permalink

    # if post is less than postdelay_secs old, skip for now and process later
    curtime = int(time.time())
    subage = curtime - subtime
    if subage < int(Settings['Config']['postdelay_secs']):
        logger.debug("%-20s: SKIP submission: %s AGE=%s user=%s http://reddit.com%s" % (subname, time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(submission.created_utc)), subage, submission.author, submission.permalink))
        return

    logger.info("%-20s: process submission: %s AGE=%s user=%s http://reddit.com%s" % (subname, time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(submission.created_utc)), subage, submission.author, submission.permalink))

    lotideHeaders =  {
        'authorization': "Bearer " + lotideToken,
        'content-type': "application/json",
        'cache-control': "no-cache",
    }

    postContent = "[link to original Reddit post](%s) by [/u/%s](%s)\n\n---\n\n" % (rsubRedditLink, authorname, authorRedditLink) 
    REGEX_TEST = r"((http|https):\/\/(.+).+?(jpg|png))"
    if re.search(REGEX_TEST, submission.url, re.IGNORECASE):
        postContent += "![%s](%s)\n\n" % (submission.url, submission.url)
    postContent += submission.selftext

    lotidePostData =  {
        "community": int(lotideCommunityID),
        "title": submission.title,
        "content_markdown": postContent,
        "href": submission.url
    }

    try:
        lotidePostResult = requests.post(Settings['lotide']['lotideurl']+"/api/unstable/posts", data=json.dumps(lotidePostData), headers=lotideHeaders)
        logger.debug("-- lotideResult: %s %s" % (lotidePostResult.status_code, lotidePostResult.content))
    except HTTPError as http_err:
            print(f'HTTP error occurred: {http_err}')
    except Exception as err:
            print(f'Other error occurred: {err}')
    
    save_processed_sql(submission.id)


def getLotideToken():
    newToken = ""
    logindata = {
            "username": Settings['lotide']['username'],
            "password": Settings['lotide']['password']
    }

    loginheaders = {
        'content-type': "application/json",
        'cache-control': "no-cache",
    }
    lotideURL = Settings['lotide']['lotideurl'] + "/api/unstable/logins"

    try:
        loginResponse = requests.post(lotideURL, data=json.dumps(logindata), headers=loginheaders)
        if loginResponse.status_code == 200:
            loginResponse.encoding = 'utf-8'
            loginJSON = loginResponse.json()
            if 'token' in loginJSON:
                return loginJSON['token']
    except HTTPError as http_err:
            print(f'HTTP error occurred: {http_err}')
    except Exception as err:
            print(f'Other error occurred: {err}')
    

# =============================================================================
# MAIN
# =============================================================================


def main():
    start_process = False
    logger.info("start program")

    # create db tables if needed
    logger.debug("Create DB tables if needed")
    create_db()

    if ENVIRONMENT == "DEV" and os.path.isfile(RUNNING_FILE):
        os.remove(RUNNING_FILE)
        logger.debug("DEV=running file removed")

    if not os.path.isfile(RUNNING_FILE):
        create_running_file()
        start_process = True
    else:
        logger.error("bot already running! Will not start.")

    # Initalize
    next_refresh_time = 0
    subList = []
    subList_prev = []
    lotideToken = ""

    while start_process and os.path.isfile(RUNNING_FILE):
        logger.debug("Start Main Loop")

        # setup lotide session
        if not lotideToken:
            lotideToken = getLotideToken()
        logger.debug("Lotide Token: %s" % lotideToken)

        # setup reddit session
        #subList = [ 'goldandblack' ]
        subList = Settings['SubredditCommunities'].keys()
        if not subList == subList_prev:
           logger.debug("Build(re) multireddit")
           multireddits = build_multireddit_groups(subList)
           for multi in multireddits:
             subreddit = reddit.subreddit('+'.join(multi))
           subList_prev = subList

        subreddit = reddit.subreddit('+'.join(multi))
        submission_stream = subreddit.new()

        try:
          # process submission stream
          for submission in submission_stream:
            if submission is None:
               break
            elif check_processed_sql(submission.id):
               continue
            else:
               process_submission(submission, lotideToken)


        # Allows the bot to exit on ^C, all other exceptions are ignored
        except KeyboardInterrupt:
            break
        except Exception as err:
            logger.exception("Unknown Exception in Main Loop")

        logger.debug("End Main Loop - Pause %s secs" % Settings['Config']['main_loop_pause_secs'])
        time.sleep(int(Settings['Config']['main_loop_pause_secs']))

    logger.info("end program")
    sys.exit()


# =============================================================================
# RUNNER
# =============================================================================

if __name__ == '__main__':
    # Reddit info
    reddit = praw.Reddit(client_id=Settings['Reddit']['client_id'],
                         client_secret=Settings['Reddit']['client_secret'],
                         password=Settings['Reddit']['password'],
                         user_agent=Settings['Reddit']['user_agent'],
                         username=Settings['Reddit']['username'])

    main()
