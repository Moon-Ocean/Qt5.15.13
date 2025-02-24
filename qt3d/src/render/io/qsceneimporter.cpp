/****************************************************************************
**
** Copyright (C) 2014 Klaralvdalens Datakonsult AB (KDAB).
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

#include "qsceneimporter_p.h"
#include <Qt3DRender/private/renderlogging_p.h>
#include <QStringList>

QT_BEGIN_NAMESPACE

namespace Qt3DRender {

QSceneImporter::QSceneImporter() : QObject(),
    m_status(Empty)
{
}

QSceneImporter::~QSceneImporter()
{
}

QSceneImporter::ParserStatus QSceneImporter::status() const
{
    return m_status;
}

QStringList QSceneImporter::errors() const
{
    return m_errors;
}

void QSceneImporter::setStatus(ParserStatus status)
{
    if (status != m_status) {
        m_status = status;
        emit statusChanged(status);
    }
}

void QSceneImporter::logError(const QString &error)
{
    m_errors.append(error);
    emit errorsChanged(m_errors);
}

void QSceneImporter::logInfo(const QString &info)
{
    qCDebug(Render::Io) << info;
}

} // namespace Qt3DRender

QT_END_NAMESPACE

#include "moc_qsceneimporter_p.cpp"
