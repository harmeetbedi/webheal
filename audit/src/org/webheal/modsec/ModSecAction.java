package org.webheal.modsec;

import java.util.HashMap;
import java.util.Map;

import org.apache.log4j.Logger;
import org.webheal.util.Decoder;


enum ModSecAction
{
    convertToLowercase {
        @Override public String normalize(String text) throws Exception
        {
            return Decoder.convertToLowercase(text);
        }
    },
    removeSelfReferences {
        @Override public String normalize(String text) throws Exception
        {
            return Decoder.removeSelfReferences(text);
        }
    },
    convertBackslashes {
        @Override public String normalize(String text) throws Exception
        {
            return Decoder.convertBackSlashes(text);
        }
    },
    compressSlashes {
        @Override public String normalize(String text) throws Exception
        {
            return Decoder.compressSlashes(text);
        }
    },
    compressWhitespace {
        @Override public String normalize(String text) throws Exception
        {
            return Decoder.compressWhitespace(text);
        }
    },
    decodeEscaped {
        @Override public String normalize(String text) throws Exception
        {
            return Decoder.decodeEscaped(text);
        }
    },
    decodeURLEncoded {
        @Override public String normalize(String text) throws Exception
        {
            return Decoder.decodeURLEncoded(text);
        }
    },
    decodeURLEncodedAgain {
        @Override public String normalize(String text) throws Exception
        {
            text = Decoder.decodeURLEncoded(text);
            return Decoder.decodeURLEncoded(text);
        }
    };
    public abstract String normalize(String text) throws Exception;

    private static final Logger LOG = Logger.getLogger(ModSecAction.class);
    private static Map<String, ModSecAction> s_map = new HashMap<String, ModSecAction>();
    static {
        for (ModSecAction nf : ModSecAction.values()) {
            s_map.put(nf.name().toUpperCase(), nf);
        }
    }

    static ModSecAction getInstance(String action)
    {
        ModSecAction nf = s_map.get(action.toUpperCase());
        return nf;
    }
}
