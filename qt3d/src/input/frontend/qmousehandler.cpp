/****************************************************************************
**
** Copyright (C) 2015 Klaralvdalens Datakonsult AB (KDAB).
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

#include "qmousehandler.h"
#include "qmousehandler_p.h"

#include <Qt3DInput/qmousedevice.h>
#include <Qt3DInput/qmouseevent.h>
#include <QtCore/QTimer>

QT_BEGIN_NAMESPACE

using namespace Qt3DCore;

namespace Qt3DInput {
/*! \internal */
QMouseHandlerPrivate::QMouseHandlerPrivate()
    : QComponentPrivate()
    , m_mouseDevice(nullptr)
    , m_containsMouse(false)
    , m_pressAndHoldTimer(new QTimer)
{
    m_shareable = false;
    m_pressAndHoldTimer->setSingleShot(true);
    m_pressAndHoldTimer->setInterval(800);
    QObject::connect(m_pressAndHoldTimer, &QTimer::timeout, [this] {
        emit q_func()->pressAndHold(m_lastPressedEvent.data());
    });
}

QMouseHandlerPrivate::~QMouseHandlerPrivate()
{
}

void QMouseHandlerPrivate::init(QObject *parent)
{
    m_pressAndHoldTimer->setParent(parent);
}

void QMouseHandlerPrivate::mouseEvent(const QMouseEventPtr &event)
{
    Q_Q(QMouseHandler);
    switch (event->type()) {
    case QEvent::MouseButtonPress:
        m_lastPressedEvent = event;
        m_pressAndHoldTimer->start();
        emit q->pressed(event.data());
        break;
    case QEvent::MouseButtonRelease:
        m_pressAndHoldTimer->stop();
        emit q->released(event.data());
        emit q->clicked(event.data());
        break;
#if QT_CONFIG(gestures)
    case QEvent::Gesture:
        emit q->clicked(event.data());
        break;
#endif
    case QEvent::MouseButtonDblClick:
        emit q->doubleClicked(event.data());
        break;
    case QEvent::MouseMove:
        m_pressAndHoldTimer->stop();
        emit q->positionChanged(event.data());
        break;
    default:
        break;
    }
}

/*!
 * \qmltype MouseHandler
 * \instantiates Qt3DInput::QMouseHandler
 * \inqmlmodule Qt3D.Input
 * \since 5.5
 * \brief Provides mouse event notification.
 *
 * \TODO
 * \sa MouseDevice, MouseEvent
 */

/*!
 * \class Qt3DInput::QMouseHandler
 * \inheaderfile Qt3DInput/QMouseHandler
 * \inmodule Qt3DInput
 *
 * \brief Provides a means of being notified about mouse events when attached to
 * a QMouseDevice instance.
 *
 * \since 5.5
 *
 * \note QMouseHandler components shouldn't be shared, not respecting that
 * condition will most likely result in undefined behaviors.
 *
 * \sa QMouseDevice, QMouseEvent
 */

/*!
    \qmlproperty MouseDevice Qt3D.Input::MouseHandler::sourceDevice

    Holds the current mouse source device of the MouseHandler instance.
 */

/*!
    \qmlproperty bool Qt3D.Input::MouseHandler::containsMouse
    \readonly

    Holds \c true if the QMouseHandler currently contains the mouse.
 */

/*!
    \qmlsignal Qt3D.Input::MouseHandler::clicked(MouseEvent mouse)

    This signal is emitted when a mouse button is clicked with the event details
    being contained within \a mouse
 */

/*!
    \qmlsignal Qt3D.Input::MouseHandler::doubleClicked(MouseEvent mouse)

    This signal is emitted when a mouse button is double clicked with the event
    details being contained within \a mouse
 */

/*!
    \qmlsignal Qt3D.Input::MouseHandler::entered()
 */

/*!
    \qmlsignal Qt3D.Input::MouseHandler::exited()
 */

/*!
    \qmlsignal Qt3D.Input::MouseHandler::pressed(MouseEvent mouse)

    This signal is emitted when a mouse button is pressed with the event details
    being contained within \a mouse
 */

/*!
    \qmlsignal Qt3D.Input::MouseHandler::released(MouseEvent mouse)

    This signal is emitted when a mouse button is released with the event
    details being contained within \a mouse
 */

/*!
    \qmlsignal Qt3D.Input::MouseHandler::pressAndHold(MouseEvent mouse)

    This signal is emitted when a mouse button is pressed and held down with the
    event details being contained within \a mouse
 */

/*!
    \qmlsignal Qt3D.Input::MouseHandler::positionChanged(MouseEvent mouse)

    This signal is emitted when the mouse position changes with the event
    details being contained within \a mouse
 */

/*!
    \qmlsignal Qt3D.Input::MouseHandler::wheel(MouseEvent mouse)

    This signal is emitted when the mouse wheel is used with the event details
    being contained within \a mouse.
 */

/*!
    \fn Qt3DInput::QMouseHandler::clicked(Qt3DInput::QMouseEvent *mouse)

    This signal is emitted when a mouse button is clicked with the event details
    being contained within \a mouse.
 */

/*!
    \fn Qt3DInput::QMouseHandler::doubleClicked(Qt3DInput::QMouseEvent *mouse)

    This signal is emitted when a mouse button is double clicked with the event
    details being contained within \a mouse.
 */

/*!
    \fn Qt3DInput::QMouseHandler::entered()
 */

/*!
    \fn Qt3DInput::QMouseHandler::exited()
 */

/*!
    \fn Qt3DInput::QMouseHandler::pressed(Qt3DInput::QMouseEvent *mouse)

    This signal is emitted when a mouse button is pressed with the event details
    being contained within \a mouse
 */

/*!
    \fn Qt3DInput::QMouseHandler::released(Qt3DInput::QMouseEvent *mouse)

    This signal is emitted when a mouse button is released with the event
    details being contained within \a mouse
 */

/*!
    \fn Qt3DInput::QMouseHandler::pressAndHold(Qt3DInput::QMouseEvent *mouse)

    This signal is emitted when a mouse button is pressed and held down with the
    event details being contained within \a mouse
 */

/*!
    \fn Qt3DInput::QMouseHandler::positionChanged(Qt3DInput::QMouseEvent *mouse)

    This signal is emitted when the mouse position changes with the event
    details being contained within \a mouse
 */

/*!
    \fn Qt3DInput::QMouseHandler::wheel(Qt3DInput::QWheelEvent *wheel)

    This signal is emitted when the mouse wheel is used with the event details
    being contained within \a wheel
 */

/*!
 * Constructs a new QMouseHandler instance with parent \a parent.
 */
QMouseHandler::QMouseHandler(QNode *parent)
    : QComponent(*new QMouseHandlerPrivate, parent)
{
    Q_D(QMouseHandler);
    d->init(this);
}

QMouseHandler::~QMouseHandler()
{
}

/*!
 * Sets the mouse device of the QMouseHandler instance to \a mouseDevice.
 */
void QMouseHandler::setSourceDevice(QMouseDevice *mouseDevice)
{
    Q_D(QMouseHandler);
    if (d->m_mouseDevice != mouseDevice) {

        if (d->m_mouseDevice)
            d->unregisterDestructionHelper(d->m_mouseDevice);

        // We need to add it as a child of the current node if it has been declared inline
        // Or not previously added as a child of the current node so that
        // 1) The backend gets notified about it's creation
        // 2) When the current node is destroyed, it gets destroyed as well
        if (mouseDevice && !mouseDevice->parent())
            mouseDevice->setParent(this);
        d->m_mouseDevice = mouseDevice;

        // Ensures proper bookkeeping
        if (d->m_mouseDevice)
            d->registerDestructionHelper(d->m_mouseDevice, &QMouseHandler::setSourceDevice, d->m_mouseDevice);

        emit sourceDeviceChanged(mouseDevice);
    }
}

// TODO Unused remove in Qt6
void QMouseHandler::sceneChangeEvent(const QSceneChangePtr &)
{
}

/*!
 * \property Qt3DInput::QMouseHandler::sourceDevice
 *
 * Holds the current mouse source device of the QMouseHandler instance.
 */
QMouseDevice *QMouseHandler::sourceDevice() const
{
    Q_D(const QMouseHandler);
    return d->m_mouseDevice;
}

/*!
 * \property Qt3DInput::QMouseHandler::containsMouse
 *
 * Holds \c true if the QMouseHandler currently contains the mouse.
 *
 * \note In this context, contains mean that the ray originating from the
 * mouse is intersecting with the Qt3DCore::QEntity that aggregates the current
 * QMouseHandler instance component.
 */
bool QMouseHandler::containsMouse() const
{
    Q_D(const QMouseHandler);
    return d->m_containsMouse;
}

/*! \internal */
void QMouseHandler::setContainsMouse(bool contains)
{
    Q_D(QMouseHandler);
    if (contains != d->m_containsMouse) {
        d->m_containsMouse = contains;
        emit containsMouseChanged(contains);
    }
}

Qt3DCore::QNodeCreatedChangeBasePtr QMouseHandler::createNodeCreationChange() const
{
    auto creationChange = Qt3DCore::QNodeCreatedChangePtr<QMouseHandlerData>::create(this);
    auto &data = creationChange->data;

    Q_D(const QMouseHandler);
    data.mouseDeviceId = qIdForNode(d->m_mouseDevice);

    return creationChange;
}

} // namespace Qt3DInput

QT_END_NAMESPACE

#include "moc_qmousehandler.cpp"
