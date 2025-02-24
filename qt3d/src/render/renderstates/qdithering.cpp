/****************************************************************************
**
** Copyright (C) 2014 Klaralvdalens Datakonsult AB (KDAB).
** Copyright (C) 2016 The Qt Company Ltd and/or its subsidiary(-ies).
** Contact: https://www.qt.io/licensing/
**
** This file is part of the Qt3D module of the Qt Toolkit.
**
** $QT_BEGIN_LICENSE:LGPL$
** Commercial License Usage
** Licensees holding valid commercial Qt licenses may use this file in
** accordance with the commercial license agreement provided with the
** Software or, alternatively, in accordance with the terms contained in
** a written agreement between you and The Qt Company. For licensing terms
** and conditions see https://www.qt.io/terms-conditions. For further
** information use the contact form at https://www.qt.io/contact-us.
**
** GNU Lesser General Public License Usage
** Alternatively, this file may be used under the terms of the GNU Lesser
** General Public License version 3 as published by the Free Software
** Foundation and appearing in the file LICENSE.LGPL3 included in the
** packaging of this file. Please review the following information to
** ensure the GNU Lesser General Public License version 3 requirements
** will be met: https://www.gnu.org/licenses/lgpl-3.0.html.
**
** GNU General Public License Usage
** Alternatively, this file may be used under the terms of the GNU
** General Public License version 2.0 or (at your option) the GNU General
** Public license version 3 or any later version approved by the KDE Free
** Qt Foundation. The licenses are as published by the Free Software
** Foundation and appearing in the file LICENSE.GPL2 and LICENSE.GPL3
** included in the packaging of this file. Please review the following
** information to ensure the GNU General Public License requirements will
** be met: https://www.gnu.org/licenses/gpl-2.0.html and
** https://www.gnu.org/licenses/gpl-3.0.html.
**
** $QT_END_LICENSE$
**
****************************************************************************/

#include "qdithering.h"
#include "qrenderstate_p.h"
#include <private/qnode_p.h>

QT_BEGIN_NAMESPACE

namespace Qt3DRender {

/*!
    \class Qt3DRender::QDithering
    \since 5.7
    \inmodule Qt3DRender
    \brief Enable dithering.

    A Qt3DRender::QDithering class enables dithering. Dithering adds noise to the
    color values to randomize quantization error in order to prevent large scale
    patterns in the final image, such as banding. Dithering is most useful when
    rendering to a surface with low color bit depth, such as RGB565 or RGBA4444.
 */

/*!
    \qmltype Dithering
    \since 5.7
    \inqmlmodule Qt3D.Render
    \inherits RenderState
    \instantiates Qt3DRender::QDithering
    \brief Enable dithering.

    A Dithering type enables dithering. Dithering adds noise to the
    color values to randomize quantization error in order to prevent large scale
    patterns in the final image, such as banding. Dithering is most useful when
    rendering to a surface with low color bit depth, such as RGB565 or RGBA4444.
 */

class QDitheringPrivate : public QRenderStatePrivate
{
public:
    QDitheringPrivate()
        : QRenderStatePrivate(Render::DitheringStateMask)
    {}

    Q_DECLARE_PUBLIC(QDithering)
};

/*!
    The constructor creates a new QDithering::QDithering instance with
    the specified \a parent.
 */
QDithering::QDithering(QNode *parent)
    : QRenderState(*new QDitheringPrivate, parent)
{
}

/*! \internal */
QDithering::~QDithering()
{
}

} // namespace Qt3DRender

QT_END_NAMESPACE

#include "moc_qdithering.cpp"
