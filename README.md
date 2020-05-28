    Under construction(準備中...)

# ts2cc: MPEG-2 TS to Closed caption texts in Python.
Parses TS packets and extracts closed captions from MPEG-2 TS recorded via [recdvb](http://www13.plala.or.jp/sat/recdvb/), [dvbv5-zap](https://howtoinstall.co/en/ubuntu/trusty/dvb-tools) and [Mirakurun](https://github.com/Chinachu/Mirakurun).  
The ts2cc is intended to be used as a datasets for NLP, so only plain text is acquired.  
recdvbやdvbv5, Mirakurunで収録したTSから字幕を抽出します。データセットとしての利用を目的としているので字幕のプレーンテキストだけを取得します。

# Features
- Extracts closed captions from TS packets regardless of Full TS or limited TS.  
Full TS, Mirakurun&EPGStation, sid/caption指定のTS のどれでもTS解析と字幕抽出をします.
- Don't print time codes of closed captions (but implements it in the future).  
いまは字幕のタイムコードを表示していませんが近々対応します。

# Requirements
- Python3

# Installation
    git clone https://github.com/camberbridge/ts2cc.git

# Get started
    $ python3 ts2cc.py infile(TS file)
    
    PMT_PIDs:  [272]
    ++++++++++++++++++++++
    かわばた（川畑）　皆様…。（２人）　こんにちは。
    今日は　ひき肉と豆をトマト味で煮込む➡
    作り置きにもピッタリなひと品です。
    クミンシードとチリパウダーの香りが味の決め手です。
    いろいろとアレンジができますので➡
    たっぷりと作って常備菜にしてはいかがでしょうか。
    では　まずは　ひき肉からです。
    まず　ひき肉に下味を付けます。
    塩です。
    塩は肉のうま味をグッと引き出してくれます。
    ...
