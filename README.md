# BYOVD
Finding and exploiting process killer drivers with LOL

# Reference 
- https://alice.climent-pommeret.red/posts/process-killer-driver/

# POC
- Ksapi64-Killer
this a poc for the ksapi64 driver this poc is somoe how working on 2 drivers\n
ksapi64.sys `SHA256: 1CD219F58B249A2E4F86553BDD649C73785093E22C87170798DAE90F193240AF`\n
ksapi64_del.sys `SHA256: 26ED45461E62D733F33671BFD0724399D866EE7606F3F112C90896CE8355392E`\n

Usage:
To use Ksapi-Killer, you need to have the ksapi64.sys driver located at the same location as the executable\n
you will be presented with an options menu where you can specify a process ID or name
(the driver name must be ksapi64.sys so rename if needed)


![poc_1](https://github.com/BlackSnufkin/BYOVD/assets/61916899/eeb62017-9451-4546-8903-042d8c0187f7)

![poc_2](https://github.com/BlackSnufkin/BYOVD/assets/61916899/3bed3148-c1c8-4717-8dc7-9eda926bc1ce)

--- 
