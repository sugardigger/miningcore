
#include "crypto/common/Algorithm.h"


xmrig::Algorithm::Family xmrig::Algorithm::family(Id id)
{
    switch (id) {
    case CN_0:
    case CN_1:
    case CN_2:
    case CN_R:
    case CN_FAST:
    case CN_HALF:
    case CN_XAO:
    case CN_RTO:
    case CN_RWZ:
    case CN_ZLS:
    case CN_DOUBLE:
	case CN_CCX:
        return CN;

#   ifdef XMRIG_ALGO_CN_LITE
    case CN_LITE_0:
    case CN_LITE_1:
        return CN_LITE;
#   endif

#   ifdef XMRIG_ALGO_CN_HEAVY
    case CN_HEAVY_0:
    case CN_HEAVY_TUBE:
    case CN_HEAVY_XHV:
        return CN_HEAVY;
#   endif

#   ifdef XMRIG_ALGO_CN_PICO
    case CN_PICO_0:
	case CN_PICO_TLO:
        return CN_PICO;
#   endif

#   ifdef XMRIG_ALGO_RANDOMX
    case RX_0:
    case RX_WOW:
    case RX_ARQ:
    case RX_SFX:
    case RX_KEVA:
        return RANDOM_X;
#   endif

#   ifdef XMRIG_ALGO_ARGON2
    case AR2_CHUKWA:
	case AR2_CHUKWA_V2:
    case AR2_WRKZ:
        return ARGON2;
#   endif

#   ifdef XMRIG_ALGO_ASTROBWT
    case ASTROBWT_DERO:
        return ASTROBWT;
#   endif

#   ifdef XMRIG_ALGO_KAWPOW
    case KAWPOW_RVN:
        return KAWPOW;
#   endif

    default:
        break;
    }

    return UNKNOWN;
}
