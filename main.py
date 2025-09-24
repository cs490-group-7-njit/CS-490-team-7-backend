import random

numbers = [random.randint(1, 100) for _ in range(5)]

print("List of random numbers:")
for num in numbers:
    print(num)