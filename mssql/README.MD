# About
You found a SQL injection on an MSSQL server, but the functionality is limited, you can’t execute commands, you can retrieve some user hashes out of a table, but they don’t crack–you can even get a NTLMv2 hash using xp_dirtree, which also doesn’t crack. All the data in the tables you see is pretty much useless. Now what?

Luckily, there is still plenty of potential for taking advantage of this vulnerability. Despite being a slightly older technique and piece of knowledge, it’s possible to extract users, groups, and machine names from an Active Directory environment via SQL injection using RID bruteforcing. While this technique was elaborated on by Scott Sutherland five years ago, it seems that many are unaware this is possible (including myself prior to coming across this great article).

# Brute force RID
The principle is pretty simple:

Find out the name of the domain
Find out the SID of the domain
Build user, group, and machine SIDs by iterating over a range of RIDs to determine names for each of the objects.

# Other uses
## Get domain SID for silver ticket forging when others means don't work out
1. Find the domain name
```sql
select default_domain();
```
2. Find out the SID of the domain
```sql
select sys.fn_varbintohexstr(SUSER_SID('{domain}\Administrator'));
```
You should get somethings like: 0x0105000000000005150000005b7bb0f398aa2245ad4a1ca4f4010000
3. Convert into SID format.
Use the `mssql_to_sid.py` script
```bash
python3 mssql_to_sid.py 0x0105000000000005150000005b7bb0f398aa2245ad4a1ca4f4010000
```
