pip install pillow cryptography piexif

# 文件 -> PNG（加密+校验+元数据）
python zpng_cli.py encode in.zip out.png --password 口令 --checksum \
  --title T --artist A --shoot-datetime "2025-10-31 14:03:00"

# PNG -> 文件
python zpng_cli.py decode out.png restored.zip --password 口令

# 文件 -> 文字
python zpng_cli.py to-text in.zip out.txt --password 口令 --checksum

# 文字 -> 文件
python zpng_cli.py from-text out.txt restored.zip --password 口令

# PNG -> 文字（不解密）
python zpng_cli.py png-to-text out.png out.txt

# 文字 -> PNG（写入元数据）
python zpng_cli.py text-to-png out.txt from-text.png --title "From Text"

