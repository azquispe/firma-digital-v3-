/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ganaseguros.validar;

import com.itextpdf.io.source.PdfTokenizer.TokenType;
import com.itextpdf.kernel.pdf.*;

import java.io.IOException;
import java.io.InputStream;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 *
 * @author ADSIB
 */
public class ContentsChecker extends PdfReader {
    public ContentsChecker(InputStream is) throws IOException {
        super(is);
    }

    protected Estado estadoFromAnnot(PdfDictionary annot) {
        if (annot.containsKey(PdfName.Subtype)) {
            if (annot.getAsName(PdfName.Subtype).equals(PdfName.Text) ||
                    annot.getAsName(PdfName.Subtype).equals(PdfName.Link) ||
                    annot.getAsName(PdfName.Subtype).equals(PdfName.FreeText)){
                return Estado.text_agregado;
            }
            if (annot.getAsName(PdfName.Subtype).equals(PdfName.Line) ||
                    annot.getAsName(PdfName.Subtype).equals(PdfName.Square) ||
                    annot.getAsName(PdfName.Subtype).equals(PdfName.Circle) ||
                    annot.getAsName(PdfName.Subtype).equals(PdfName.Polygon) ||
                    annot.getAsName(PdfName.Subtype).equals(PdfName.PolyLine)) {
                return Estado.graph_agregado;
            }
            if (annot.getAsName(PdfName.Subtype).equals(PdfName.Highlight) ||
                    annot.getAsName(PdfName.Subtype).equals(PdfName.Underline) ||
                    annot.getAsName(PdfName.Subtype).equals(PdfName.Squiggly) ||
                    annot.getAsName(PdfName.Subtype).equals(PdfName.StrikeOut)) {
                return Estado.highlight_agregado;
            }
            if (!annot.getAsName(PdfName.Subtype).equals(PdfName.Widget)) {
                return Estado.desconocido_agregado;
            }
        }
        return null;
    }

    /**
     * Verifica si la firma cubre todo el documento.
     * @param sign Dictionary que da acceso a la firma.
     * @return 
     */
    public Estado checkElementAdded(PdfDictionary sign) {
        long[] byteRange = sign.getAsArray(PdfName.ByteRange).toLongArray();
        int widgets = 0, signatures = 0; Map<PdfName, List<PdfDictionary>> map = new TreeMap<>();
        try {
            if (4 != byteRange.length || 0 != byteRange[0] || tokens.getSafeFile().length() != byteRange[2] + byteRange[3]) {
                tokens.seek(byteRange[2] + byteRange[3]);
                while (true) {
                    try {
                        if (tokens.nextToken()) {
                            PdfDictionary dict = null;
                            if (tokens.getTokenType() == TokenType.Obj) {
                                PdfObject obj = readObject(true, true);
                                if (obj.isDictionary()) {
                                    dict = (PdfDictionary)obj;
                                }
                            } else if (tokens.getTokenType() == TokenType.StartDic) {
                                dict = readDictionary(true);
                            }
                            if (dict != null) {
                                if (!map.containsKey(dict.getAsName(PdfName.Type))) {
                                    map.put(dict.getAsName(PdfName.Type), new LinkedList());
                                }
                                map.get(dict.getAsName(PdfName.Type)).add(dict);
                                if (dict.containsKey(PdfName.Type) && dict.containsKey(PdfName.Subtype)) {
                                    if (dict.getAsName(PdfName.Type).equals(PdfName.Annot) && dict.getAsName(PdfName.Subtype).equals(PdfName.Widget)) {
                                        widgets++;
                                        if (dict.containsKey(PdfName.V) && dict.containsKey(PdfName.FT)) {
                                            if (dict.getAsName(PdfName.FT).equals(PdfName.Sig)) {
                                                signatures++;
                                            }
                                        } else {
                                            if (dict.containsKey(PdfName.FT) && dict.getAsName(PdfName.FT).equals(PdfName.Sig)) {
                                                widgets--;
                                            }
                                        }
                                    }
                                } else {
                                    if (dict.getAsName(PdfName.Type).equals(PdfName.Page) && dict.containsKey(PdfName.Parent)) {
                                        PdfDictionary parent = dict.getAsDictionary(PdfName.Parent);
                                        if (parent.containsKey(PdfName.Kids)) {
                                            PdfArray array = parent.getAsArray(PdfName.Kids);
                                            for (PdfObject object : array) {
                                                if (object.isDictionary()) {
                                                    PdfDictionary dictKids = (PdfDictionary)object;
                                                    if (dictKids.containsKey(PdfName.Annots)) {
                                                        PdfArray array2 = dictKids.getAsArray(PdfName.Annots);
                                                        for (PdfObject object2 : array2) {
                                                            if (object2.getIndirectReference().getOffset() > byteRange[2] + byteRange[3]) {
                                                                PdfDictionary dict2 = (PdfDictionary)object2;
                                                                if (dict2.containsKey(PdfName.Subtype) && dict2.getAsName(PdfName.Subtype).equals(PdfName.Widget)) {
                                                                    widgets++;
                                                                    if (dict2.containsKey(PdfName.V) && dict2.containsKey(PdfName.FT) && dict.containsKey(PdfName.Contents)) {
                                                                        if (dict2.getAsName(PdfName.FT).equals(PdfName.Sig)) {
                                                                            signatures++;
                                                                        }
                                                                    } else {
                                                                        if (dict.containsKey(PdfName.FT) && dict.getAsName(PdfName.FT).equals(PdfName.Sig)) {
                                                                            widgets--;
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        } else {
                            break;
                        }
                    } catch (Exception ignore) {
                    }
                }
                if (widgets > 0) {
                    if (widgets == signatures) {
                        if (map.containsKey(PdfName.Annot)) {
                            for (PdfDictionary annot : map.get(PdfName.Annot)) {
                                Estado estado = estadoFromAnnot(annot);
                                if (estado != null) {
                                    return estado;
                                }
                            }
                        }
                        if (map.containsKey(PdfName.Page)) {
                            for (PdfDictionary page : map.get(PdfName.Page)) {
                                if (page.containsKey(PdfName.Annots)) {
                                    PdfArray array = page.getAsArray(PdfName.Annots);
                                    for (PdfObject object : array) {
                                        if (object.isDictionary()) {
                                            Estado estado = estadoFromAnnot((PdfDictionary)object);
                                            if (estado != null) {
                                                return estado;
                                            }
                                        }
                                    }
                                }
                                if (page.containsKey(PdfName.Parent)) {
                                    PdfDictionary parent = page.getAsDictionary(PdfName.Parent);
                                    if (parent.containsKey(PdfName.Kids)) {
                                        PdfArray array = parent.getAsArray(PdfName.Kids);
                                        for (PdfObject obj : array) {
                                            if (obj.isDictionary()) {
                                                PdfDictionary dict = (PdfDictionary)obj;
                                                if (dict.containsKey(PdfName.Contents)) {
                                                    if (dict.get(PdfName.Contents).isArray()) {
                                                        PdfArray contents = dict.getAsArray(PdfName.Contents);
                                                        for (PdfObject cont : contents) {
                                                            if (cont.getIndirectReference().getOffset() > byteRange[2] + byteRange[3]) {
                                                                return Estado.desconocido_agregado;
                                                            }
                                                        }
                                                    } else {
                                                        if (dict.get(PdfName.Contents).getIndirectReference().getOffset() > byteRange[2] + byteRange[3]) {
                                                            return Estado.desconocido_agregado;
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        return Estado.widget_firma_agregado;
                    } else {
                        return Estado.widget_otro_agregado;
                    }
                } else {
                    for (PdfName key : map.keySet()) {
                        for (PdfDictionary dict : map.get(key)) {
                            if (dict.containsKey(PdfName.BBox) && dict.containsKey(PdfName.Resources)) {
                                PdfObject res = dict.get(PdfName.Resources);
                                if (res.isDictionary()) {
                                    if (((PdfDictionary)res).size() > 0) {
                                        return Estado.desconocido_agregado;
                                    }
                                }
                            }
                        }
                    }
                    if (map.containsKey(PdfName.Annot) || map.containsKey(PdfName.Annots) || map.containsKey(PdfName.Highlight)) {
                        return Estado.desconocido_agregado;
                    }
                    if (map.containsKey(PdfName.Page)) {
                        for (PdfDictionary page : map.get(PdfName.Page)) {
                            if (page.containsKey(PdfName.Parent)) {
                                PdfDictionary parent = page.getAsDictionary(PdfName.Parent);
                                if (parent.containsKey(PdfName.Kids)) {
                                    PdfArray array = parent.getAsArray(PdfName.Kids);
                                    for (PdfObject obj : array) {
                                        if (obj.isDictionary()) {
                                            PdfDictionary dict = (PdfDictionary)obj;
                                            if (dict.containsKey(PdfName.Contents)) {
                                                if (dict.get(PdfName.Contents).isArray()) {
                                                    PdfArray contents = dict.getAsArray(PdfName.Contents);
                                                    for (PdfObject cont : contents) {
                                                        if (cont.getIndirectReference().getOffset() > byteRange[2] + byteRange[3]) {
                                                            return Estado.desconocido_agregado;
                                                        }
                                                    }
                                                } else {
                                                    if (dict.get(PdfName.Contents).getIndirectReference().getOffset() > byteRange[2] + byteRange[3]) {
                                                        return Estado.desconocido_agregado;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            if (page.containsKey(PdfName.Annot) || page.containsKey(PdfName.Annots)) {
                                return Estado.desconocido_agregado;
                            }
                        }
                    }
                    if (map.containsKey(PdfName.Sig)) {
                        return Estado.widget_firma_agregado;
                    }
                }
            }
        } catch (IOException ignore) {
            // That's not expected because if the signature is invalid, it should have already failed
            return Estado.desconocido_agregado;
        }

        return Estado.sin_cambios;
    }

    public enum Estado {
        widget_firma_agregado,
        widget_otro_agregado,
        text_agregado,
        graph_agregado,
        highlight_agregado,
        desconocido_agregado,
        sin_cambios
    }
}