Under construction(準備中...)

# ts2cc in Python
Parses TS packets and extracts closed captions from TS recorded via "recdvb", "dvbv5" and "Mirakurun". The ts2cc is intended to be used as a datasets for NLP, so only plain text is acquired.
  recdvbやdvbv5, Mirakurunで収録したTSから字幕を抽出します。自然言語処理のデータセットとしての利用を目的としているので字幕のプレーンテキストだけを取得します。

# Features
- Extracts closed captions from TS packets redardless of Full TS or limited TS.
  Full TS, Mirakurun&EPGStation, sid/caption指定のTS のどれでもTS解析と字幕抽出をします.
- Don't print time codes of closed captions (but implements it in the future).
  いまは字幕のタイムコードを表示していませんが近々対応します。

# Requirements
- Python3

# Installation
    git clone https://github.com/camberbridge/ts2cc.git

# Get started
    python3 ts2cc.py infile(TS file)
