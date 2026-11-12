"""``decrypt`` returns one instance per row, in the order of the rows. An app
that selects a column outside the model, such as a generated key, pairs it
with the instances by position, as the README says.
"""

from _sync_contract import User, user

from stackencrypt import Cipher


def test_decrypt_returns_the_instances_in_the_order_of_the_rows():
    cipher = Cipher(User)
    rows = cipher.encrypt([user(n) for n in range(6)])

    assert cipher.decrypt(rows[::-1]) == [user(n) for n in reversed(range(6))]
    assert cipher.decrypt_rows(rows[::2]) == [
        {"id": n, "email": user(n).email} for n in range(0, 6, 2)
    ]
