import smtplib
import random
import time

USERNAME = 'pythonforsuccess@gmail.com'
PASSWORD = 'pvnamgpuyqbzrito'

numbers = list(range(100, 1000))
random_code = []
for i in range(2):
    random_number = random.choice(numbers)
    random_code.append(random_number)
joined_list = int(''.join(str(i) for i in random_code))


class SendEmail:
    def __init__(self, email, name):
        self.email = email
        self.name = name
        self.joined_list = ''

    def shuffle_code(self):
        new_numbers = list(range(100, 1000))
        new_random_code = []
        for u in range(2):
            new_random_number = random.choice(new_numbers)
            random_code.append(new_random_number)
        self.joined_list = ''.join(str(u) for u in new_random_code)

    def send_code(self):
        with smtplib.SMTP('smtp.gmail.com', port=587) as connection:
            connection.starttls()
            connection.login(user=USERNAME, password=PASSWORD)
            connection.sendmail(
                from_addr=USERNAME,
                to_addrs=self.email,
                msg=f"Subject:Request To Reset Password \n\n"
                    f"Hello {self.name}. \nYou requested to change your password on The People's Blog.\n"
                    f"DO NOT SHARE THIS CODE WITH ANYONE. \nYour verification code is: {int(joined_list)}."
                    f"\nIf you did not make this request, kindly log in to your account and change your password. "
                    f"\nThank you, the people's blog, 2023."
            )
