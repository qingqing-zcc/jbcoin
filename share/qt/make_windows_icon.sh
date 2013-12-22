#!/bin/bash
# create multiresolution windows icon
ICON_DST=../../src/qt/res/icons/zccoin.ico

convert ../../src/qt/res/icons/zccoin-16.png ../../src/qt/res/icons/zccoin-32.png ../../src/qt/res/icons/zccoin-48.png ${ICON_DST}
