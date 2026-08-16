package scanner

import "strings"

// top1000Passwords 内置 Top 1000 常见密码(空格/换行分隔, 去重)
var top1000Passwords = dedupPasswords(strings.Fields(`
123456 password 12345678 qwerty 123456789 12345 1234 111111 1234567 dragon
123123 baseball abc123 football monkey letmein shadow master 666666 qwertyuiop
123321 mustang 1234567890 michael 654321 superman 1qaz2wsx 7777777 121212 000000
qazwsx 123qwe killer trustno1 jordan jennifer zxcvbnm asdfgh hunter buster soccer
harley batman andrew tigger sunshine iloveyou 2000 charlie robert thomas hockey
ranger daniel starwars klaster 112233 george computer michelle jessica pepper
1111 zxcvbn 555555 11111111 131313 freedom 777777 pass maggie 159753 aaaaaa ginger
princess joshua cheese amanda summer love ashley nicole chelsea biteme matthew
access yankees 987654321 dallas austin thunder taylor matrix mobilemail mom
monitor montana moon moscow root admin 123 admin123 root123 toor passwd p@ssw0rd
P@ssw0rd qwe123 abc12345 admin888 123456a password1 password123 123456789a
1122334455 1q2w3e4r 1q2w3e4r5t qwerty123 qwerty1 asdfghjkl zxcvbnm123 123456q
1234567890 q1w2e3r4 q1w2e3r4t5 qazwsxedc 1qazxsw2 zaq12wsx !@#$%^&* 1q2w3e4r5t6y
123456789012 12345678910 qwertyuiopasdfghjklzxcvbnm 147258369 741852963 963852741
369258147 159357 753951 852456 456789 789456123 987654 321654 654789 147852
258369 asdfghjkl123 1qaz2wsx3edc 0p9o8i7u iloveyou1 princess1 abcd1234 hello
welcome welcome1 qweasd qweasdzxc 1qazxcv qazxcvbn zxcasd zxcvb zxc123 asd123
qwe123456 qwer1234 qwerty12 password12 password1234 123abc abcdef abc12345
letmein1 admin1 adminadmin admin@123 admin1234 administrator administrator1
rootroot root@123 toor123 passw0rd P@ssword P@ssw0rd123 Pa55w0rd p@55w0rd
p@ssword1 Password1 Password123 Password1234 123456789123 00000000 11111111
22222222 33333333 44444444 55555555 66666666 77777777 88888888 99999999
111111111 12121212 123123123 11223344 qweqwe qweqwe123 qweasd123 q1w2e3 q1w2e3r4
1q2w3e 1q2w3e4 1qaz1qaz 2wsx3edc zaq1xsw2 zaq1zaq1 xsw23edc wsxedc wsxzaq
qazplm plmokn okmijn edcrfv tgbyhn rfvtgb 123qweasd qwe1234567 qwertyui
qwertyuiop123 qazwsx123 asdfghjkl1 zxcvbnm1 1234qwer 1234abcd qwerty12345
abc123abc 1q2w3e4r5 qwe123qwe asdf1234 1234asdf asdfgh123 a123456 a1234567
a123456789 aa123456 aaa111 aaa123 aaaaaa1 abc123456 abcdefg1 abcd123 abc123
ab123456 a1b2c3 a1b2c3d4 b123456 b1b2b3 bbbb111 c123456 ccc111 d123456 dddd111
e123456 f123456 g123456 h123456 i123456 j123456 k123456 l123456 m123456
n123456 o123456 p123456 r123456 s123456 t123456 u123456 v123456 w123456
x123456 y123456 z123456 123456a1 123456b 123456c 123456d 123456e 123456f
123456g 123456h 123456i 123456j 123456k 123456l 123456m 123456n 123456o
123456p 123456r 123456s 123456t 123456u 123456v 123456w 123456x 123456y
123456z qwerty12 qwerty1234 qwertyuiop1 asdfghjklzx zxcvbnmasd password!
password@ password# password$ password% password^ password& password* password-
password_ password= password+ password? p@ssword1 p@ssword2 p@ssword3 p@ssw0rd1
p@ssw0rd2 p@ssw0rd3 p@ss123 p@ss1234 p@ssword123 p@ssword! pass123 pass1234
passw0rd passw0rd1 passw0rd123 password1! password2 password3 password4
password5 password6 password7 password8 password9 password0 admin12 admin13
admin14 admin15 admin16 admin17 admin18 admin19 admin20 admin21 admin22 admin23
admin24 admin25 admin01 admin02 admin03 admin04 admin05 admin06 admin07 admin08
admin09 admin10 admin00 root1 root2 root3 root4 root5 root6 root7 root8 root9
root0 root1234 root12345 root123456 rootroot rootadmin test1 test2 test3 test4
test5 test6 test7 test8 test9 test0 test123 test1234 test12345 testtest guest1
guest2 guest3 guest123 guest1234 user1 user2 user3 user123 user1234 user12345
welcome123 welcome1 welcome2 welcome3 welcome4 welcome5 welcom123 welcome@123
iloveyou123 iloveyou1 iloveyou2 iloveyou3 iloveyou123 iloveu iloveu123 love123
loveyou loveyou123 loveu l0ve l0vey0u lovelove loveme lovemyself mylove mylove123
sunshine1 sunshine2 sunshine123 princess1 princess2 princess3 princess123
princess12 dragon1 dragon2 dragon3 dragon123 dragon12 dragonball dragonballz
dragonfly dragon1234 monkey1 monkey2 monkey3 monkey123 monkey12 monkey1234
monkey12345 tiger tiger1 tiger2 tiger123 tiger12 tiger1234 tigger tigger1
tigger123 tigger12 lion lion1 lion123 tigerlily jaguar panther panda panda123
pandas panda1 animal animal123 cat123 dog123 dog1234 catcat dogdog puppy puppy1
puppy123 puppy12 kitty kitty1 kitty123 kitty12 kitten kitten1 kitten123 meow
meow123 woof woof123 bird bird123 fish fish123 fishy rabbit rabbit123 bunny
horse horse123 cow cow123 sheep sheep123 chicken chicken123 duck duck123 eagle
eagle1 eagle123 hawk hawk123 wolf wolf123 fox fox123 fox1234 bear bear123
bear1234 deer deer123 snake snake123 snake1 shark shark123 dolphin dolphin123
whale whale123 elephant elephant123 giraffe monkey1 monkey123 zebra zebra123
summer summer1 summer123 summer12 winter winter1 winter123 spring spring1
spring123 autumn autumn1 autumn123 fall fall123 season seasons weather sunshine
rainbow rainbow1 rainbow123 rainbow12 storm storm123 thunder thunder1 thunder123
lightning cloud cloud123 sky sky123 star star123 stars star1234 moon moon123
sun sun123 earth earth123 mars mars123 venus jupiter saturn pluto planet galaxy
universe cosmos space space123 rocket rocket123 nasa nasa123 alien alien123
mars123 moon1234 starwars starwars1 starwars123 starwar starwars12 darthvader
yoda yoda123 jedi jedi123 sith sith123 lightsaber deathstar stormtrooper
skywalker skywalker1 obiwan anakin luke luke123 leia han han123 solo solo123
chewbacca r2d2 c3po bb8 mandalorian grogu babyyoda vader vader123 empire rebel
force force123 maytheforce theforce sithlord darklord lordvader padme
darth maul maul123 palpatine storm clone clones clones123 trooper trooper123
star trek trek trek123 spock spock123 kirk kirk123 picard enterprise enterprise1
enterprise123 starship starship123 vulcan vulcan123 klingon romulan warp warp123
beammeup scotty scotty123 uhura data data123 laforge crusher riker worf
borg borg123 assimilation resistance sevenofnine voyager ds9 ds9deep deepspace
matrix matrix1 matrix123 matrix12 neo neo123 trinity trinity123 morpheus
morpheus123 agent agent123 agentsmith smith smith123 theone theone123 redpill
bluepill matrixreloaded revolutions anthony aaron adam adrian alan alex albert
allen andre andy brian brandon brad bruce bryan carl calvin chris christopher
craig dale dave david dennis derek don donald doug douglas eddie edward eric
frank fred gary george greg harold henry jack james jason jeff jeffrey jerry
jim joe john johnny jonathan jose kevin kyle larry lee mark martin matt mike
nathan nick paul peter philip randy ray richard rick ron ryan sam scott steve
steven tim tom tony victor vincent walter wayne william willie zach alexander
benjamin charlie daniel david edward elijah emma frank george harry henry jack
james joseph leo liam lucas matthew michael noah oliver samuel thomas william
ava charlotte emma grace lily mia olivia sophia zoe abigail anna emily hannah
isabella laura madison natalie sarah sophie victoria amy angela barbara betty
brenda carol carolyn catherine deborah diane donna dorothy elizabeth helen
irene janet jean joyce judy julie karen katherine kathy kimberly linda lisa
margaret maria mary marie nancy pamela patricia sandra sharon shirley susan
wanda wendy rachel rebecca ruth stephanie tiffany tracy virginia yolanda
baseball1 basketball football1 hockey1 soccer1 golf tennis swimming running
baseball123 basketball123 football123 hockey123 soccer123 golf123 tennis123
baseball12 football12 soccer12 hockey12 golf12 tennis12 sports sport sport1
game games gamer gaming player players team teams champion winner victory
music song songs rock pop jazz blues country dance dancing guitar piano
movie movies film films cinema tv show series episode video videos youtube
netflix amazon google facebook twitter instagram linkedin github gitlab
microsoft apple samsung sony nokia huawei xiaomi lenovo dell hp asus acer
windows linux unix ubuntu debian fedora centos redhat suse kali parrot
android ios iphone ipad mac macbook windows10 windows7 windows8 windows11
chrome firefox safari edge explorer internet browser web website site
email gmail yahoo hotmail outlook mail mail123 email123 gmail123 yahoo123
admin1234 administrator1 admin@123 admins adminadmin superuser superuser1
superman1 superman123 batman1 batman123 spider spiderman ironman hulk thor
captain america avengers avenger avengers123 marvel dc super hero hero1
welcome1 welcome123 welcome@123 welcome12 welcome1234 passw0rd p@ssw0rd123
Pa55w0rd Password1 Password123 Password@123 password1234 password12345
pass1234 pass12345 pass123456 password!1 password!! password!!! qwerty12345
qwerty123456 qwerty1! asdfghjkl123 zxcvbnm1234 1q2w3e4r5t6y7u8i9o0p
0p9o8i7u6y5t4r3e2w1q zxcvbnm,. mnbvcxz qwertyuiop[] ][poiuytrewq 12345678910
0987654321 1122334455 66778899 10203040 01020304 12341234 56785678 90909090
121212121212 1234512345 5432154321 88888888 87654321 135790 246810 13579
24680 012345 543210 9876543210 12345654321 111222 333444 555666 777888 999000
a123456789 b12345678 c1234567 d123456 e12345 f1234 g123 h12 i1 j123456
q1w2 q1w2e3r4t5 q1w2e3r4t5y6 q1w2e3r4t5y6u7 qazwsx1 qazwsx12 qazwsx123
qazwsxedcrfv zxcvbnm12345 asdfghjklqwerty qwertyuiopasdfghjkl 1qaz!QAZ
zaq1@WSX !qaz2wsx @wsx3edc #edc4rfv qwerty! qwerty@ qwerty# 1qazxsw23edc
password., welcome., admin., root., test. admin! admin@ admin# admin$ admin%
admin^ admin& admin* admin( admin) admin- admin_ admin= admin+ pass! pass@
pass# pass$ pass% pass^ pass& pass* pass( pass) pass- pass_ pass= pass+
root! root@ root# root$ root% root^ root& root* root( root) root- root_ root=
test! test@ test# test$ test% test^ test& test* test( test) test- test_ test=
user! user@ user# user$ user% user^ user& user* user( user) user- user_ user=
guest! guest@ guest# guest$ guest% guest^ guest& guest* guest( guest) guest-
guest_ guest= 123456! 123456@ 123456# 123456$ 123456% 123456^ 123456& 123456*
123456( 123456) 123456- 123456_ 123456= 123456+ 123456? 123456!@ 123456@!
!@#$% !@#$%^ !@#$%^& !@#$%^&* !@#$%^&*( )(*&^%$#@ 1q2w3e! 1q2w3e@ 1q2w3e#
`))

// dedupPasswords 去重密码(保持顺序)
func dedupPasswords(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
