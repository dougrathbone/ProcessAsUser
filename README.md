# ProcessAsUser
A c# managed library for executing processes as another user, and mimicking the normal Process.Start(); framework methods used normally.

## Setup requirements to start work

1. Create a user named "childUser" with the password "test123" to run.
2. Open `Secpol.msc` and grant this user `Local Policies > Logon as a batch job`
3. In `Secpol.msc` give the account you will be executing as (ie the one running VS) `Local Policies > User Rights Assignment > Adjust memory quotas for a prcess`
4. Your Visual Studio Instance must be running as Administrator to debug.
