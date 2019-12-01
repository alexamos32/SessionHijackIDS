import time

class UserLog:
    def __init__(self):
        self.users = dict()
    
    def print_log(self):
        for user in self.users:
            print(user)
            print(*(self.users[user]['mac']), 'COUNT:', self.users[user]['count'])


    def add_user(self, user, mac, timestamp):
        if user in self.users:
            self.users[user]['count'] += 1
            self.users[user]['timestamp'].append(timestamp)
            self.users[user]["mac"].append(mac)
        else:
            self.users[user] = dict()
            self.users[user]['count'] = 1
            self.users[user]['timestamp'] = [timestamp]
            self.users[user]['mac'] = [mac]         

    def search_user(self, user):
        if user in self.users:
            return True
        return False
  
    def check_login_count(self):
        userList = list()
        for user in self.users:
            if self.users[user]['count'] >= 2:
               # print("YOOOOOOOOOOOOOOO")
                userList.append(user)
                userList.append(self.users[user]['mac']) 
               # userList.append(self.users[user]['timestamp'])    
        return userList
    
    def cleanup(self):
        time1hour = time.time() - 3600
        for user in self.users:
            i = 0
            if self.users[user]['count'] == 0:
                continue
            
            while self.users[user]['timestamp'][i] < time1hour:
                del(self.users[user]['timestamp'][i])
                del(self.users[user]['mac'][i])
                self.users[user]['count'] -= 1

                if self.users[user]['count'] == 0:
                    break
            



