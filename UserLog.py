class UserLog:
    def __init__(self):
        self.users = dict()

    def add_user(self, user, sip, timestamp):
        if user in self.users:
            self.users[user]['count'] += 1
            self.users[user]['timestamp'].append(timestamp)
            self.users[user]["sip"].append(sip)
        else:
            self.users[user] = dict()
            self.users[user]['count'] = 1
            self.users[user]['timestamp'] = [timestamp]
            self.users[user]['sip'] = [sip]
            

    def search_user(self, user):
        if user in self.users:
            return True
        return False
