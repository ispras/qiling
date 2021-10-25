import sys
sys.path.append("../..")

from qiling.core import Qiling
from qiling.const import QL_VERBOSE


def stm32f411_freertos():
    ql = Qiling(["../rootfs/mcu/stm32f411/os-demo.hex"],                    
        archtype="cortex_m", profile="stm32f411", verbose=QL_VERBOSE.DEBUG)

    ql.hw.create('usart2')
    ql.hw.create('rcc')
    ql.hw.create('gpioa')

    ql.hw.systick.set_ratio(100)
    ql.run(count=200000)

if __name__ == "__main__":
    stm32f411_freertos()